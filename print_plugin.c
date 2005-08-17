/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2005 by Paolo Lucente
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
#include "ports_aggr.h"
#include "util.h"
#include "crc32.c"

/* Functions */
void print_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct networks_table nt;
  struct networks_cache nc;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  time_t t, now;
  int timeout, ret, num; 
#if defined (HAVE_MMAP)
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  unsigned char *rgptr;
  int pollagain = 0;
  u_int32_t seq = 0;
  int rg_err_count = 0;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);

  /* signal handling */
  signal(SIGINT, P_exit_now);
  signal(SIGUSR1, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

#if defined (HAVE_MMAP)
  status->wakeup = TRUE;
#endif

  if (!config.print_refresh_time)
    config.print_refresh_time = DEFAULT_PRINT_REFRESH_TIME;

  timeout = config.print_refresh_time*1000;

  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET|COUNT_SUM_AS))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  
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
  t = roundoff_time(refresh_deadline, config.sql_history_roundoff);
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
          Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
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
	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        (*insert_func)(data);

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

void P_cache_insert(struct pkt_data *data)
{
  unsigned int modulo = P_cache_modulo(&data->primitives);
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
	  Log(LOG_WARNING, "WARN ( %s/%s ): Unable to write data: try with a larger 'print_cache_entries' value.\n", 
			  config.name, config.type);
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
    cache_ptr->flow_counter = ntohl(data->flo_num);
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
      cache_ptr->flow_counter += ntohl(data->flo_num);
      cache_ptr->bytes_counter += ntohl(data->pkt_len);
    }
    else {
      /* entry invalidated; restarting counters */
      cache_ptr->packet_counter = ntohl(data->pkt_num);
      cache_ptr->flow_counter = ntohl(data->flo_num);
      cache_ptr->bytes_counter = ntohl(data->pkt_len);
      cache_ptr->valid = TRUE;
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }
  }
}

void P_cache_flush(struct chained_cache *queue[], int index)
{
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
  char src_mac[17], dst_mac[17], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN];
  int j;

  if (config.print_markers) printf("--START (%u+%u)--\n", refresh_deadline-config.print_refresh_time,
		  			config.print_refresh_time);

  for (j = 0; j < index; j++) {
    printf("%-5d  ", queue[j]->id);
#if defined (HAVE_L2)
    etheraddr_string(queue[j]->eth_shost, src_mac);
    printf("%-17s  ", src_mac);
    etheraddr_string(queue[j]->eth_dhost, dst_mac);
    printf("%-17s  ", dst_mac);
    printf("%-5d  ", queue[j]->vlan_id); 
#endif
#if defined ENABLE_IPV6
    if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("%-45d  ", ntohl(queue[j]->src_ip.address.ipv4.s_addr));
#else
    if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("%-15d  ", ntohl(queue[j]->src_ip.address.ipv4.s_addr));
#endif
    else {
      addr_to_str(src_host, &queue[j]->src_ip);
#if defined ENABLE_IPV6
      printf("%-45s  ", src_host);
#else
      printf("%-15s  ", src_host);
#endif
    }
#if defined ENABLE_IPV6
    if (config.what_to_count & COUNT_DST_AS) printf("%-45d  ", ntohl(queue[j]->dst_ip.address.ipv4.s_addr));
#else
    if (config.what_to_count & COUNT_DST_AS) printf("%-15d  ", ntohl(queue[j]->dst_ip.address.ipv4.s_addr));
#endif
    else {
      addr_to_str(dst_host, &queue[j]->dst_ip);
#if defined ENABLE_IPV6
      printf("%-45s  ", dst_host);
#else
      printf("%-15s  ", dst_host);
#endif
    }
    printf("%-5d     ", queue[j]->src_port);
    printf("%-5d     ", queue[j]->dst_port);
    printf("%-10s  ", _protocols[queue[j]->proto].name);
    printf("%-3d    ", queue[j]->tos);
    printf("%-10u  ", queue[j]->packet_counter);
    printf("%-10u  ", queue[j]->flow_counter);
    printf("%u\n", queue[j]->bytes_counter);
  }

  if (config.print_markers) printf("--END--\n");
}

void P_write_stats_header()
{
  printf("ID     ");
#if defined (HAVE_L2)
  printf("SRC MAC            ");
  printf("DST MAC            ");
  printf("VLAN   ");
#endif
#if defined ENABLE_IPV6
  printf("SRC IP                                         ");
  printf("DST IP                                         ");
#else
  printf("SRC IP           ");
  printf("DST IP           ");
#endif
  printf("SRC PORT  ");
  printf("DST PORT  ");
  printf("PROTOCOL    ");
  printf("TOS    ");
  printf("PACKETS     ");
  printf("FLOWS       ");
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
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to grab enough memory (requested: %u bytes). Exiting ...\n", 
		      config.name, config.type, size);
      exit(1);
    }
  }

  return obj;
}

void P_sum_host_insert(struct pkt_data *data)
{
  struct in_addr ip;
#if defined ENABLE_IPV6
  struct in6_addr ip6;
#endif

  if (data->primitives.dst_ip.family == AF_INET) {
    ip.s_addr = data->primitives.dst_ip.address.ipv4.s_addr;
    data->primitives.dst_ip.address.ipv4.s_addr = 0;
    data->primitives.dst_ip.family = 0;
    P_cache_insert(data);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    P_cache_insert(data);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    insert_accounting_structure(data);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    insert_accounting_structure(data);
    return;
  }
#endif
}

void P_sum_port_insert(struct pkt_data *data)
{
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  P_cache_insert(data);
  data->primitives.src_port = port;
  P_cache_insert(data);
}

#if defined (HAVE_L2)
void P_sum_mac_insert(struct pkt_data *data)
{
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  P_cache_insert(data);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  P_cache_insert(data);
}
#endif

void P_exit_now(int signum)
{
  exit(0);
}
