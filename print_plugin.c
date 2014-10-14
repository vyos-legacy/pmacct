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

#define __PRINT_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "print_plugin.h"
#include "net_aggr.h"
#include "util.h"
#include "crc32.c"

/* Functions */
void print_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct networks_table nt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  time_t t, now;
  int timeout, ret; 
  unsigned int modulo;
#if defined (HAVE_MMAP)
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  unsigned char *rgptr;
  int pollagain = 0;
  u_int32_t seq = 0;
  int rg_err_count = 0;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));

#if defined (HAVE_MMAP)
  status->wakeup = TRUE;
#endif

  /* checks */
  if (config.what_to_count & COUNT_SUM_HOST) {
    Log(LOG_ERR, "ERROR: Option available only in memory table operations\nExiting ...\n\n");
    exit(1);
  }

  if (!config.print_refresh_time)
    config.print_refresh_time = DEFAULT_PRINT_REFRESH_TIME;

  timeout = config.print_refresh_time*1000;

  if (config.networks_file) load_networks(config.networks_file, &nt);
  
  pp_size = sizeof(struct pkt_primitives);
  dbc_size = sizeof(struct chained_cache);
  if (!config.print_cache_entries) config.print_cache_entries = PRINT_CACHE_ENTRIES; 
  memset(&sa, 0, sizeof(struct scratch_area));
  sa.num = config.print_cache_entries*AVERAGE_CHAIN_LEN;
  sa.size = sa.num*dbc_size;

  pipebuf = (unsigned char *) Malloc(config.buffer_size);
  cache = (struct chained_cache *) Malloc(config.print_cache_entries*dbc_size); 
  queries_queue = (struct chained_cache **) Malloc((sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  sa.base = (unsigned char *) Malloc(sa.size);
  sa.ptr = sa.base;
  sa.next = NULL;

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = now; 
  t = roundoff_time(refresh_deadline);
  while ((t+config.print_refresh_time) < refresh_deadline) t += config.print_refresh_time;
  refresh_deadline = t;
  refresh_deadline += config.print_refresh_time; /* it's a deadline not a basetime */

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.print_cache_entries*sizeof(struct chained_cache));
  memset(queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(sa.base, 0, sa.size);

  P_write_stats_header();

  /* plugin main loop */
  for(;;) {
    poll_again:
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;
    now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      if (qq_ptr) {
        switch (fork()) {
        case 0: /* Child */
	  P_cache_purge(queries_queue, qq_ptr);
          exit(0);
        default: /* Parent */
          P_cache_flush(queries_queue, qq_ptr);
	  refresh_deadline += config.print_refresh_time; 
	  qq_ptr = FALSE;
          break;
        }
      }
      break;
    default: /* we received data */
#if !defined (HAVE_MMAP)
      if ((ret = read(pipe_fd, pipebuf, config.buffer_size)) == 0) 
        exit(1); /* we exit silently; something happened at the write end */

      if (ret < 0) goto poll_again;
#else
      if (!pollagain) {
	seq++;
	seq %= MAX_SEQNUM;
      }

      pollagain = FALSE;
      if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
	exit(1); /* we exit silently; something happened at the write end */

      if (ret < 0) {
	pollagain = TRUE;
	goto poll_again;
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

      /* lazy refresh time handling */ 
      if (now > refresh_deadline) {
        if (qq_ptr) {
          switch (fork()) {
          case 0: /* Child */
	    P_cache_purge(queries_queue, qq_ptr);
            exit(0);
          default: /* Parent */
            P_cache_flush(queries_queue, qq_ptr);
	    refresh_deadline += config.print_refresh_time; 
	    qq_ptr = FALSE;
            break;
	  }
        }
      } 

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	if (config.what_to_count & COUNT_SRC_NET)
	  binsearch(&nt, &data->primitives.src_ip);
	
	if (config.what_to_count & COUNT_DST_NET)
	  binsearch(&nt, &data->primitives.dst_ip);

        modulo = P_cache_modulo(&data->primitives); 
        P_cache_insert(data, modulo);
	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) data++;
      }
    }
  }
}

unsigned int P_cache_modulo(struct pkt_primitives *srcdst)
{
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  
  return modulo %= config.print_cache_entries;
}

void P_cache_insert(struct pkt_data *data, unsigned int modulo)
{
  struct chained_cache *cache_ptr = &cache[modulo];
  struct pkt_primitives *srcdst = &data->primitives;

  start:
  if (memcmp(cache_ptr, srcdst, sizeof(struct pkt_primitives)) != 0) { 
    /* aliasing of entries */
    if (cache_ptr->valid == TRUE) { 
      if (cache_ptr->next) {
	cache_ptr = cache_ptr->next;
	goto start;
      }
      else {
	cache_ptr = P_cache_attach_new_node(cache_ptr); 
	if (!cache_ptr) {
	  Log(LOG_WARNING, "WARN: Unable to write data: try with a larger 'print_cache_entries' value.\n");
	  return; 
	}
	else {
	  queries_queue[qq_ptr] = cache_ptr;
	  qq_ptr++;
	}
      }
    }
    else {
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }

    /* we add the new entry in the cache */
    memcpy(cache_ptr, srcdst, sizeof(struct pkt_primitives));
    cache_ptr->packet_counter = ntohl(data->pkt_num);
    cache_ptr->bytes_counter = ntohl(data->pkt_len);
    cache_ptr->valid = TRUE;
  }
  else {
    if (cache_ptr->valid == TRUE) {
      /* additional check: would counters overflow ? */
      /*if ((cache_ptr->packet_counter > UINT32TMAX) ||
	       (cache_ptr->bytes_counter > UINT32TMAX)) {
	// P_handle_collision(&cache[modulo]);
      } */

      /* everything is ok; summing counters */
      cache_ptr->packet_counter += ntohl(data->pkt_num);
      cache_ptr->bytes_counter += ntohl(data->pkt_len);
    }
    else {
      /* entry invalidated; restarting counters */
      cache_ptr->packet_counter = ntohl(data->pkt_num);
      cache_ptr->bytes_counter = ntohl(data->pkt_len);
      cache_ptr->valid = TRUE;
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }
  }
}

void P_cache_flush(struct chained_cache *queue[], int index)
{
  unsigned char *qptr = (unsigned char *) *queue;
  int j;

  for (j = 0; j < index; j++) {
    queue[j]->valid = FALSE;
    queue[j]->next = NULL;
  }

  /* rewinding scratch area stuff */
  sa.ptr = sa.base;
}

struct chained_cache *P_cache_attach_new_node(struct chained_cache *elem)
{
  if ((sa.ptr+sizeof(struct chained_cache)) <= (sa.base+sa.size)) {
    sa.ptr += sizeof(struct chained_cache);
    elem->next = (struct chained_cache *) sa.ptr;
    return (struct chained_cache *) sa.ptr;
  }
  else return NULL; /* XXX */
}

void P_cache_purge(struct chained_cache *queue[], int index)
{
  char *src_mac, *dst_mac, *src_host, *dst_host;
  int j;

  if (config.print_markers) printf("--START (%u+%u)--\n", refresh_deadline-config.print_refresh_time,
		  			config.print_refresh_time);

  for (j = 0; j < index; j++) {
    printf("%-5d  ", queue[j]->id);
    src_mac = (char *) ether_ntoa(queue[j]->eth_shost);
    printf("%-17s  ", src_mac);
    dst_mac = (char *) ether_ntoa(queue[j]->eth_dhost);
    printf("%-17s  ", dst_mac);
    printf("%-5d  ", queue[j]->vlan_id); 
    src_host = inet_ntoa(queue[j]->src_ip);
    printf("%-15s  ", src_host);
    dst_host = inet_ntoa(queue[j]->dst_ip);
    printf("%-15s  ", dst_host);
    printf("%-5d     ", queue[j]->src_port);
    printf("%-5d     ", queue[j]->dst_port);
    printf("%-10s  ", _protocols[queue[j]->proto].name);
    printf("%-10u  ", queue[j]->packet_counter);
    printf("%u\n", queue[j]->bytes_counter);
  }

  if (config.print_markers) printf("--END--\n");
}

void P_write_stats_header()
{
  printf("ID     ");
  printf("SRC MAC            ");
  printf("DST MAC            ");
  printf("VLAN   ");
  printf("SRC IP           ");
  printf("DST IP           ");
  printf("SRC PORT  ");
  printf("DST PORT  ");
  printf("PROTOCOL    ");
  printf("PACKETS     ");
  printf("BYTES\n");
}

void *Malloc(unsigned int size)
{
  unsigned char *obj;

  obj = (unsigned char *) malloc(size);  
  if (!obj) {
    sbrk(size); 
    obj = (unsigned char *) malloc(size);
    if (!obj) {
      Log(LOG_ERR, "ERROR: Unable to grab enough memory (requested: %u bytes). Exiting ...\n", size);
      exit(1);
    }
  }

  return obj;
}
