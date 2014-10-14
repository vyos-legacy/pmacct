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

#define __SERVER_C

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"

/* functions */
int build_query_server(char *path_ptr)
{
  struct sockaddr_un sAddr;
  int sd, rc;

  sd=socket(AF_UNIX, SOCK_STREAM, 0);
  if (sd < 0) {
    Log(LOG_ERR, "ERROR: cannot open socket.\n");
    exit(1);
  }

  sAddr.sun_family = AF_UNIX;
  strcpy(sAddr.sun_path, path_ptr); 
  unlink(path_ptr);
  
  rc = bind(sd, (struct sockaddr *) &sAddr,sizeof(sAddr));
  if (rc < 0) { 
    Log(LOG_ERR, "ERROR: cannot bind to file %s .\n", path_ptr);
    exit(1);
  } 

  chmod(path_ptr, S_IRUSR|S_IWUSR|S_IXUSR|
                  S_IRGRP|S_IWGRP|S_IXGRP|
                  S_IROTH|S_IWOTH|S_IXOTH);

  setnonblocking(sd);
  listen(sd, 1);
  Log(LOG_INFO, "OK: waiting for data on: '%s'\n", path_ptr);

  return sd;
}


void process_query_data(int sd, unsigned char *buf, int len, int forked)
{
  struct acc *acc_elem = 0, tmpbuf;
  struct bucket_desc bd;
  struct query_header *q, *uq;
  struct query_entry request;
  struct reply_buffer rb;
  unsigned char *elem, *bufptr;
  int following_chain=0;
  unsigned int idx;
  struct pkt_data dummy;

  memset(&dummy, 0, sizeof(struct pkt_data));
  memset(&rb, 0, sizeof(struct reply_buffer));
  memcpy(rb.buf, buf, sizeof(struct query_header));
  rb.len = LARGEBUFLEN-sizeof(struct query_header);
  rb.packed = sizeof(struct query_header);

  /* arranging some pointer */
  uq = (struct query_header *) buf;
  q = (struct query_header *) rb.buf;
  rb.ptr = rb.buf+sizeof(struct query_header);
  bufptr = buf+sizeof(struct query_header);

  if (config.debug) Log(LOG_DEBUG, "Processing data received from client ...\n");

  if (config.imt_plugin_passwd) {
    if (!strncmp(config.imt_plugin_passwd, q->passwd, MIN(strlen(config.imt_plugin_passwd), 8)));
    else return;
  }

  elem = (unsigned char *) a;

  if (q->type & WANT_STATS) {
    q->what_to_count = config.what_to_count; 
    for (idx = 0; idx < config.buckets; idx++) {
      if (!following_chain) acc_elem = (struct acc *) elem;
      if (acc_elem->packet_counter && !acc_elem->reset_flag)
	enQueue_elem(sd, &rb, acc_elem, sizeof(struct pkt_data));
      if (acc_elem->next != NULL) {
        if (config.debug) Log(LOG_DEBUG, "Following chain in reply ...\n");
        acc_elem = acc_elem->next;
        following_chain = TRUE;
        idx--;
      }
      else {
        elem += sizeof(struct acc);
        following_chain = FALSE;
      }
    }
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
  else if (q->type & WANT_STATUS) {
    for (idx = 0; idx < config.buckets; idx++) {

      /* Administrativia */
      following_chain = FALSE;
      bd.num = 0;
      bd.howmany = 0;
      acc_elem = (struct acc *) elem;

      do {
        if (following_chain) acc_elem = acc_elem->next;
        if (acc_elem->packet_counter && !acc_elem->reset_flag) bd.howmany++;
        bd.num = idx; /* we need to avoid this redundancy */
        following_chain = TRUE;
      } while (acc_elem->next != NULL);

      enQueue_elem(sd, &rb, &bd, sizeof(struct bucket_desc));
      elem += sizeof(struct acc);
    }
    send(sd, rb.buf, rb.packed, 0);
  }
  else if (q->type & WANT_MATCH || q->type & WANT_COUNTER) {
    unsigned int j;
   
    q->what_to_count = config.what_to_count;
    for (j = 0; j < uq->num; j++, bufptr += sizeof(struct query_entry)) {
      memcpy(&request, bufptr, sizeof(struct query_entry));
      if (config.debug) Log(LOG_DEBUG, "Searching into accounting structure ...\n"); 
      if (request.what_to_count == config.what_to_count) { 
        acc_elem = search_accounting_structure(&request.data);
        if (acc_elem) { 
	  if (acc_elem->packet_counter && !acc_elem->reset_flag) {
	    enQueue_elem(sd, &rb, acc_elem, sizeof(struct pkt_data));
	    if (q->type & WANT_RESET) {
	      if (forked) set_reset_flag(acc_elem);
	      else reset_counters(acc_elem);
	    }
	  }
	  else {
	    if (q->type & WANT_COUNTER) enQueue_elem(sd, &rb, &dummy, sizeof(struct pkt_data));
	  }
        }
	else {
	  if (q->type & WANT_COUNTER) enQueue_elem(sd, &rb, &dummy, sizeof(struct pkt_data));
	}
      }
      else {
        struct pkt_primitives tbuf;  
	struct pkt_data abuf;
        following_chain = FALSE;
	elem = (unsigned char *) a;
	memset(&abuf, 0, sizeof(abuf));

        for (idx = 0; idx < config.buckets; idx++) {
          if (!following_chain) acc_elem = (struct acc *) elem;
	  if (acc_elem->packet_counter && !acc_elem->reset_flag) {
	    mask_elem(&tbuf, acc_elem, request.what_to_count); 
            if (!memcmp(&tbuf, &request.data, sizeof(struct pkt_primitives))) {
	      if (q->type & WANT_COUNTER) Accumulate_Counters(&abuf, acc_elem); 
	      else enQueue_elem(sd, &rb, acc_elem, sizeof(struct pkt_data)); /* q->type == WANT_MATCH */
	      if (q->type & WANT_RESET) set_reset_flag(acc_elem);
	    }
          }
          if (acc_elem->next) {
            acc_elem = acc_elem->next;
            following_chain = TRUE;
            idx--;
          }
          else {
            elem += sizeof(struct acc);
            following_chain = FALSE;
          }
        }
	if (q->type & WANT_COUNTER) enQueue_elem(sd, &rb, &abuf, sizeof(struct pkt_data)); /* enqueue accumulated data */
      }
    }
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
}

void mask_elem(struct pkt_primitives *d, struct acc *s, u_int32_t w)
{
  memset(d, 0, sizeof(struct pkt_primitives));

  if (w & COUNT_SRC_MAC) memcpy(d->eth_shost, s->eth_shost, ETH_ADDR_LEN); 
  if (w & COUNT_DST_MAC) memcpy(d->eth_dhost, s->eth_dhost, ETH_ADDR_LEN); 
  if (w & COUNT_VLAN) d->vlan_id = s->vlan_id; 
  if ((w & COUNT_SRC_HOST) || (w & COUNT_SRC_AS)) {
    if (s->src_ip.family == AF_INET) d->src_ip.address.ipv4.s_addr = s->src_ip.address.ipv4.s_addr; 
#if defined ENABLE_IPV6
    else if (s->src_ip.family == AF_INET6) memcpy(&d->src_ip.address.ipv6,  &s->src_ip.address.ipv6, sizeof(struct in6_addr));
#endif
    d->src_ip.family = s->src_ip.family;
  }
  if ((w & COUNT_DST_HOST) || (w & COUNT_DST_AS)) {
    if (s->src_ip.family == AF_INET) d->dst_ip.address.ipv4.s_addr = s->dst_ip.address.ipv4.s_addr; 
#if defined ENABLE_IPV6
    else if (s->dst_ip.family == AF_INET6) memcpy(&d->dst_ip.address.ipv6,  &s->dst_ip.address.ipv6, sizeof(struct in6_addr));
#endif
    d->dst_ip.family = s->dst_ip.family;
  }
  if (w & COUNT_SRC_PORT) d->src_port = s->src_port; 
  if (w & COUNT_DST_PORT) d->dst_port = s->dst_port; 
  if (w & COUNT_IP_TOS) d->tos = s->tos;
  if (w & COUNT_IP_PROTO) d->proto = s->proto; 
  if (w & COUNT_ID) d->id = s->id; 
}

void enQueue_elem(int sd, struct reply_buffer *rb, void *elem, int size)
{
  if ((rb->packed + size) < rb->len) {
    memcpy(rb->ptr, elem, size);
    rb->ptr += size;
    rb->packed += size; 
  }
  else {
    send(sd, rb->buf, rb->packed, 0);
    rb->len = LARGEBUFLEN;
    memset(rb->buf, 0, sizeof(rb->buf));
    rb->packed = 0;
    rb->ptr = rb->buf;
    memcpy(rb->ptr, elem, size);
    rb->ptr += size;
    rb->packed += size;
  }
}

void Accumulate_Counters(struct pkt_data *abuf, struct acc *elem)
{
  abuf->pkt_len += elem->bytes_counter;
  abuf->pkt_num += elem->packet_counter;
}
