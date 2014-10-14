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
  Log(LOG_INFO, "OK: waiting for data on: %s .\n", path_ptr);

  return sd;
}


void process_query_data(int sd, unsigned char *buf, int len)
{
  struct acc *acc_elem = 0;
  struct bucket_desc bd;
  struct query_header *q;
  struct pkt_primitives addr;
  char lbuf[LARGEBUFLEN], *elem, *lbufptr, *lbufbase;
  int counter=0, packed=sizeof(struct query_header); 
  int following_chain=0, buflen = LARGEBUFLEN-sizeof(struct query_header);
  unsigned int i;

  memset(lbuf, 0, LARGEBUFLEN);
  memcpy(lbuf, buf, len);

  /* arranging some pointer */
  q = (struct query_header *) lbuf;
  lbufptr = lbuf+sizeof(struct query_header);
  lbufbase = lbuf+sizeof(struct query_header);

  if (config.debug) Log(LOG_DEBUG, "Processing data received from client ...\n");

  if (config.imt_plugin_passwd) {
    if (!strncmp(config.imt_plugin_passwd, q->passwd, MIN(strlen(config.imt_plugin_passwd), 8)));
    else return;
  }

  elem = (char *) a;

  /* We should increase elegance ;) */
#if defined (HAVE_MMAP)
  if (q->type & WANT_RESET) {
    if (config.what_to_count != q->what_to_count) {
      q->type ^= WANT_RESET;
      if (config.debug) Log(LOG_DEBUG, "DEBUG: Reset request ignored: not exact match.\n");
    }
  }
#endif

  if (q->type & WANT_STATS) {
    memset(lbufbase, 0, buflen);
    q->what_to_count = config.what_to_count; 
    for (i = 0; i < config.buckets; i++) {
      if (!following_chain) acc_elem = (struct acc *) elem;
#if !defined (HAVE_MMAP)
      if (acc_elem->packet_counter) {
#else
      if (acc_elem->packet_counter && !acc_elem->reset_flag) {
#endif
        if ((packed + sizeof(struct acc)) < buflen) {
          memcpy(lbufptr, acc_elem, sizeof(struct acc));
          lbufptr += sizeof(struct acc);
          packed += sizeof(struct acc);
          if (config.debug) counter++;
        }
        else {
          if (config.debug) {
            Log(LOG_DEBUG, "Entries: %d\n", counter);
            counter = 0;
          }
          send (sd, lbuf, packed, 0);
	  buflen = LARGEBUFLEN;
          memset(lbuf, 0, buflen);
          packed = 0;
          lbufptr = lbuf;
          memcpy(lbufptr, acc_elem, sizeof(struct acc));
          lbufptr += sizeof(struct acc);
          packed += sizeof(struct acc);
          if (config.debug) counter++;
        }
      }
      if (acc_elem->next != NULL) {
        if (config.debug) Log(LOG_DEBUG, "Following chain in reply ...\n");
        acc_elem = acc_elem->next;
        following_chain = TRUE;
        i--;
      }
      else {
        elem += sizeof(struct acc);
        following_chain = FALSE;
      }
    }
    if (config.debug) {
      Log(LOG_DEBUG, "Entries: %d\n", counter);
      counter = 0;
    }
    send (sd, lbuf, packed, 0);
  }
  // else if (q->type == WANT_ERASE) /* removed */ 
  else if (q->type & WANT_STATUS) {
    memset(lbufbase, 0, buflen);
    for (i = 0; i < config.buckets; i++) {

      /* Administrativia */
      following_chain = FALSE;
      bd.num = 0;
      bd.howmany = 0;
      acc_elem = (struct acc *) elem;

      do {
        if (following_chain) acc_elem = acc_elem->next;
#if !defined (HAVE_MMAP)
        if (acc_elem->packet_counter) bd.howmany++;
#else
        if (acc_elem->packet_counter && !acc_elem->reset_flag) bd.howmany++;
#endif
        bd.num = i; /* we need to avoid this redundancy */
        following_chain = TRUE;
      } while (acc_elem->next != NULL);

      if ((packed + sizeof(struct bucket_desc)) < buflen) {
        memcpy(lbufptr, &bd, sizeof(struct bucket_desc));
        lbufptr += sizeof(struct bucket_desc);
        packed += sizeof(struct bucket_desc);
      }
      else {
        if (config.debug) Log(LOG_DEBUG, "Sending status, up to bucket %d ...\n", i);
        send(sd, lbuf, packed, 0);
	buflen = LARGEBUFLEN;
        memset(lbuf, 0, buflen);
        packed = 0;
        lbufptr = lbuf;
        memcpy(lbufptr, &bd, sizeof(struct bucket_desc));
        lbufptr += sizeof(struct bucket_desc);
        packed += sizeof(struct bucket_desc);
      }
      elem += sizeof(struct acc);
    }
    send(sd, lbuf, packed, 0);
  }
  else if (q->type & WANT_MRTG) {
    memcpy(&addr, lbufptr, sizeof(struct pkt_primitives)); 
    if (config.debug) Log(LOG_DEBUG, "Searching into accounting structure ...\n");
    memset(lbufbase, 0, buflen);
    acc_elem = search_accounting_structure(&addr);
    if (!acc_elem) packed += sizeof(int); 
    else {
      memcpy(lbufptr, acc_elem, sizeof(struct acc));
#if defined (HAVE_MMAP)
      if (((struct acc *)lbufptr)->reset_flag) {
	((struct acc *)lbufptr)->packet_counter = 0;
	((struct acc *)lbufptr)->bytes_counter = 0;
      }
      if (q->type & WANT_RESET) set_reset_flag(acc_elem);
#endif
      packed += sizeof(struct acc);
    }
    send(sd, lbuf, packed, 0);
  }
  else if (q->type & WANT_MATCH) {
    unsigned int what_to_count = q->what_to_count;

    q->what_to_count = config.what_to_count; 
    memcpy(&addr, lbufptr, sizeof(struct pkt_primitives));
    memset(lbufbase, 0, buflen);
    if (config.debug) Log(LOG_DEBUG, "Searching into accounting structure ...\n"); 
    if (what_to_count == config.what_to_count) { 
      acc_elem = search_accounting_structure(&addr);
      if (acc_elem) { 
#if !defined (HAVE_MMAP)
	if (acc_elem->packet_counter) {
#else
	if (acc_elem->packet_counter && !acc_elem->reset_flag) {
#endif
          memcpy(lbufptr, acc_elem, sizeof(struct acc));
#if defined (HAVE_MMAP)
	  if (q->type & WANT_RESET) set_reset_flag(acc_elem);
#endif
          packed += sizeof(struct acc);
	}
      }
      send(sd, lbuf, packed, 0);
    }
    else {
      struct pkt_primitives tbuf;  

      for (i = 0; i < config.buckets; i++) {
        if (!following_chain) acc_elem = (struct acc *) elem;
#if !defined (HAVE_MMAP)
	if (acc_elem->packet_counter) {
#else
	if (acc_elem->packet_counter && !acc_elem->reset_flag) {
#endif
	  mask_elem(&tbuf, acc_elem, what_to_count); 
          if (!memcmp(&tbuf, &addr, sizeof(struct pkt_primitives))) {
            if ((packed + sizeof(struct acc)) < buflen) {
              memcpy(lbufptr, acc_elem, sizeof(struct acc));
              lbufptr += sizeof(struct acc);
              packed += sizeof(struct acc);
              if (config.debug) counter++;
            }
            else {
              if (config.debug) {
                Log(LOG_DEBUG, "Entries: %d\n", counter);
                counter = 0;
              }
              send (sd, lbuf, packed, 0);
	      buflen = LARGEBUFLEN;
              memset(lbuf, 0, buflen);
              packed = 0;
              lbufptr = lbuf;
              memcpy(lbufptr, acc_elem, sizeof(struct acc));
              lbufptr += sizeof(struct acc);
              packed += sizeof(struct acc);
              if (config.debug) counter++;
	    }
	  }
        }
        if (acc_elem->next) {
          acc_elem = acc_elem->next;
          following_chain = TRUE;
          i--;
        }
        else {
          elem += sizeof(struct acc);
          following_chain = FALSE;
        }
      }
      if (config.debug) {
        Log(LOG_DEBUG, "Entries: %d\n", counter);
        counter = 0;
      }
      send (sd, lbuf, packed, 0);
    }
  }
}

void mask_elem(struct pkt_primitives *d, struct acc *s, unsigned int w)
{
  memset(d, 0, sizeof(struct pkt_primitives));

  if (w & COUNT_SRC_MAC) memcpy(d->eth_shost, s->eth_shost, ETH_ADDR_LEN); 
  if (w & COUNT_DST_MAC) memcpy(d->eth_dhost, s->eth_dhost, ETH_ADDR_LEN); 
  if (w & COUNT_VLAN) d->vlan_id = s->vlan_id; 
  if (w & COUNT_SRC_HOST) d->src_ip.s_addr = s->src_ip.s_addr; 
  if (w & COUNT_DST_HOST) d->dst_ip.s_addr = s->dst_ip.s_addr; 
  if (w & COUNT_SRC_PORT) d->src_port = s->src_port; 
  if (w & COUNT_DST_PORT) d->dst_port = s->dst_port; 
  if (w & COUNT_IP_PROTO) d->proto = s->proto; 
}
