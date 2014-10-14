/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2004 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "plugin_hooks.h"
#include "imt_plugin.h"
#include "net_aggr.h"

/* Functions */
void imt_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct sockaddr cAddr;
  struct acc *acc_elem;
  struct pkt_data *data;
  struct networks_table nt;
  struct networks_table_entry *nte = NULL;
  unsigned char srvbuf[SRVBUFLEN];
  unsigned char *pipebuf;
  char path[] = "/tmp/collect.pipe";
  unsigned int insert_status;
  short int go_to_clear = FALSE;
#if defined (HAVE_MMAP)
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  unsigned char *rgptr;
  int pollagain = 0;
  u_int32_t seq = 0;
  int rg_err_count = 0;
#else 
  short int go_to_reset = FALSE;
#endif

  fd_set read_descs, bkp_read_descs; /* select() stuff */
  int select_fd;
  int cLen, num, sd, sd2;

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));

#if defined (HAVE_MMAP)
  status->wakeup = TRUE;
#endif

  /* a bunch of default definitions and post-checks */
  pipebuf = (unsigned char *) malloc(config.buffer_size);

  setnonblocking(pipe_fd);
  memset(pipebuf, 0, config.buffer_size);
  no_more_space = FALSE;

  if (config.networks_file) load_networks(config.networks_file, &nt);

  if ((!config.num_memory_pools) && (!have_num_memory_pools))
    config.num_memory_pools = NUM_MEMORY_POOLS;
  
  if (!config.memory_pool_size) config.memory_pool_size = MEMORY_POOL_SIZE;  
  else {
    if (config.memory_pool_size < sizeof(struct acc)) {
      Log(LOG_ERR, "ERROR: minimum size for memory pools is: %d bytes\n", sizeof(struct acc));
      exit(1);
    }
  }

  if (!config.imt_plugin_path) config.imt_plugin_path = path; 
  if (!config.buckets) config.buckets = MAX_HOSTS;

  init_memory_pool_table(config);
  if (mpd == NULL) {
    Log(LOG_ERR, "ERROR: unable to allocate memory pools table\n");
    exit(1);
  }

  current_pool = request_memory_pool(config.buckets*sizeof(struct acc));
  if (current_pool == NULL) {
    Log(LOG_ERR, "ERROR: unable to allocate first memory pool, try with larger value.\n");
    exit(1);
  }
  a = current_pool->base_ptr;

  lru_elem_ptr = malloc(config.buckets*sizeof(struct acc *));
  if (lru_elem_ptr == NULL) {
    Log(LOG_ERR, "ERROR: unable to allocate LRU element pointers.\n");
    exit(1);
  }
  else memset(lru_elem_ptr, 0, config.buckets*sizeof(struct acc *));

  current_pool = request_memory_pool(config.memory_pool_size);
  if (current_pool == NULL) {
    Log(LOG_ERR, "ERROR: unable to allocate more memory pools, try with larger value.\n");
    exit(1);
  }

  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGINT, exit_now); /* exit lane */

  /* building a server for interrogations by clients */
  sd = build_query_server(config.imt_plugin_path);
  cLen = sizeof(cAddr);

  /* preparing for synchronous I/O multiplexing */
  select_fd = 0;
  FD_ZERO(&read_descs);
  FD_SET(sd, &read_descs);
  if (sd > select_fd) select_fd = sd;
  FD_SET(pipe_fd, &read_descs);
  if (pipe_fd > select_fd) select_fd = pipe_fd;
  select_fd++;
  memcpy(&bkp_read_descs, &read_descs, sizeof(read_descs));

  /* plugin main loop */
  for(;;) {
    select_again:
    memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));
    num = select(select_fd, &read_descs, NULL, NULL, NULL);
    if (num < 0) goto select_again;  

    /* doing server tasks */
    if (FD_ISSET(sd, &read_descs)) {
      sd2 = accept(sd, &cAddr, &cLen);
      setblocking(sd2);
      num = recv(sd2, srvbuf, SRVBUFLEN, 0);
      if (((struct query_header *)srvbuf)->type == WANT_ERASE) go_to_clear = TRUE;  
      else {
        switch (fork()) {
        case 0: /* Child */
          close(sd);
          if (num > 0) process_query_data(sd2, srvbuf, num);
	  else {
	    if (config.debug) Log(LOG_DEBUG, "DEBUG: recv() '%d' incoming bytes. errno: %d\n", num, errno);
          }
          if (config.debug) Log(LOG_DEBUG, "DEBUG: Closing connection with client ...\n");
          close(sd2);
          exit(0);
        default: /* Parent */
#if !defined (HAVE_MMAP)
          if (((struct query_header *)srvbuf)->type & WANT_RESET) {
	    if (((struct query_header *)srvbuf)->what_to_count == config.what_to_count)
	      go_to_reset = TRUE;
	    else {
	      if (config.debug) Log(LOG_DEBUG, "DEBUG: Reset request ignored: not exact match.\n");
	    }
	  }
#endif
          close(sd2);
        }
      }
    }

    /* clearing stats if requested */
    if (go_to_clear) {
      clear_memory_pool_table();
      current_pool = request_memory_pool(config.buckets*sizeof(struct acc));
      if (current_pool == NULL) {
        Log(LOG_ERR, "ERROR: Cannot allocate my first memory pool, try with larger value.\n");
        exit(1);
      }
      a = current_pool->base_ptr;

      current_pool = request_memory_pool(config.memory_pool_size);
      if (current_pool == NULL) {
        Log(LOG_ERR, "ERROR: Cannot allocate more memory pools, try with larger value.\n");
        exit(1);
      }
      go_to_clear = FALSE;
      no_more_space = FALSE;
    }

#if !defined (HAVE_MMAP)
    /* resetting counters if requested */
    if (go_to_reset) {
      struct acc *acc_elem;
      unsigned char *elem = srvbuf+sizeof(struct query_header);

      acc_elem = search_accounting_structure((struct pkt_primitives *)elem);
      if (acc_elem) {
        acc_elem->packet_counter = 0;
        acc_elem->bytes_counter = 0;
      }

      go_to_reset = FALSE;
    }
#endif

    if (FD_ISSET(pipe_fd, &read_descs)) {
#if !defined (HAVE_MMAP)
      if ((num = read(pipe_fd, pipebuf, config.buffer_size)) == 0)
        exit(1); /* we exit silently; something happened at the write end */

      if (num < 0) goto select_again;
#else
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
      }

      pollagain = FALSE;
      if ((num = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
        exit(1); /* we exit silently; something happened at the write end */

      if (num < 0) {
        pollagain = TRUE;
        goto select_again;
      }

      memcpy(pipebuf, rgptr, config.buffer_size);
      if (((struct ch_buf_hdr *)pipebuf)->seq != seq) {
        rg_err_count++;
        if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
          Log(LOG_ERR, "ERROR: We are missing data.\n");
          Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
          Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%d'.\n", config.pipe_size);
          Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%d'.\n", config.buffer_size);
          Log(LOG_ERR, "- increase system maximum socket size.\n\n");
          seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	}
      }
#endif

      if (num > 0) {
	data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));
        insert_status = 0;
        acc_elem = NULL;

	while (((struct ch_buf_hdr *)pipebuf)->num) {
          if (config.what_to_count == COUNT_SUM_HOST) {
	    struct pkt_data addr;

	    memset(&addr, 0, sizeof(addr));
	    addr.primitives.src_ip.s_addr = data->primitives.src_ip.s_addr; 
	    addr.pkt_num = data->pkt_num;
	    addr.pkt_len = data->pkt_len;
            acc_elem = insert_accounting_structure(&addr);
            addr.primitives.src_ip.s_addr = data->primitives.dst_ip.s_addr;
            acc_elem = insert_accounting_structure(&addr);
            insert_status |= INSERT_ALREADY_DONE;
          }

	  if (config.what_to_count & COUNT_SRC_NET) 
	    binsearch(&nt, &data->primitives.src_ip);

	  if (config.what_to_count & COUNT_DST_NET) 
	    binsearch(&nt, &data->primitives.dst_ip);

          if (!insert_status)
            acc_elem = insert_accounting_structure(data);

	  ((struct ch_buf_hdr *)pipebuf)->num--;
	  if (((struct ch_buf_hdr *)pipebuf)->num) data++;
        }
      }
    } 
  }
}

void exit_now(int signum)
{
  exit(0);
}
