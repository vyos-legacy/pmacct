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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __IP_FRAG_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_frag.h"
#include "jhash.h"
#include "util.h"

u_int16_t ipft_total_nodes;  
u_int32_t prune_deadline;
u_int32_t trivial_hash_rnd = 140281; /* ummmh */

// u_int32_t count = 0; /* XXX: remove */

void init_ip_fragment_handler()
{
  ipft_total_nodes = 0;

  memset(ipft, 0, sizeof(ipft));
  lru_list.root = (struct ip_fragment *) malloc(sizeof(struct ip_fragment)); 
  lru_list.last = lru_list.root;
  memset(lru_list.root, 0, sizeof(struct ip_fragment));
  prune_deadline = time(NULL)+PRUNE_INTERVAL;
}

int ip_fragment_handler(struct packet_ptrs *pptrs)
{
  u_int32_t now = time(NULL);

  if (now > prune_deadline) {
    prune_old_fragments(PRUNE_OFFSET);
    prune_deadline = now+PRUNE_INTERVAL;
  }
  return find_fragment(pptrs);
}

int find_fragment(struct packet_ptrs *pptrs)
{
  struct my_iphdr *iphp = (struct my_iphdr *)pptrs->iph_ptr;
  struct ip_fragment *fp, *candidate = NULL, *last_seen = NULL;
  u_int32_t now = time(NULL);
  unsigned int bucket = hash_fragment(iphp->ip_id, iphp->ip_src.s_addr,
				      iphp->ip_dst.s_addr, iphp->ip_p);

  for (fp = ipft[bucket]; fp; fp = fp->next) {
    if (fp->ip_id == iphp->ip_id && fp->ip_src == iphp->ip_src.s_addr &&
	fp->ip_dst == iphp->ip_dst.s_addr && fp->ip_p == iphp->ip_p) {
      /* fragment found; will check for its deadline */
      if (fp->deadline > now) {
	if (fp->got_first) {
	  pptrs->tlh_ptr = fp->tlhdr; 
	  return TRUE;
	}
	else {
	  if (!(iphp->ip_off & htons(IP_OFFMASK))) {
	    /* we got our first fragment */
	    fp->got_first = TRUE;
	    memcpy(fp->tlhdr, pptrs->tlh_ptr, sizeof(struct my_tlhdr));

	    fp->a += ntohs(iphp->ip_len);
	    iphp->ip_len = htons(fp->a);
	    fp->a = 0;
            return TRUE;
	  }
	  else { /* we still don't have the first fragment; increase accumulator */
	    fp->a += ntohs(iphp->ip_len);
	    return FALSE;
	  } 
	}
      } 
      else {
	candidate = fp;
	goto create;
      }
    }
    if ((fp->deadline < now) && !candidate) {
      // if (ipft_total_nodes > count) { /* XXX: remove */
        // printf("nodes: %u\n", ipft_total_nodes);
	// count += 500;
      // }
      candidate = fp; 
    }
    last_seen = fp;
  } 

  create:
  if (candidate) return create_fragment(candidate, TRUE, bucket, pptrs);
  else return create_fragment(last_seen, FALSE, bucket, pptrs); 
}

int create_fragment(struct ip_fragment *fp, u_int8_t is_candidate, unsigned int bucket, struct packet_ptrs *pptrs)
{
  struct my_iphdr *iphp = (struct my_iphdr *)pptrs->iph_ptr;
  struct ip_fragment *newf;

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) { 
      newf = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));
      if (!newf) { 
	prune_old_fragments(0);
	newf = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));
	if (!newf) return FALSE;
      }
      else ipft_total_nodes++;
      memset(newf, 0, sizeof(struct ip_fragment));
      fp->next = newf;
      newf->prev = fp;  
      lru_list.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = lru_list.last;
      lru_list.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */ 
        fp->lru_prev->lru_next = fp->lru_next; 
	fp->lru_next->lru_prev = fp->lru_prev;
	lru_list.last->lru_next = fp;
	fp->lru_prev = lru_list.last;
	fp->lru_next = NULL;
	lru_list.last = fp;
      }
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */ 
    fp = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));  
    if (!fp) {
      prune_old_fragments(0);
      fp = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));
      if (!fp) return FALSE;
    }
    else ipft_total_nodes++;
    memset(fp, 0, sizeof(struct ip_fragment));
    ipft[bucket] = fp;
    lru_list.last->lru_next = fp; /* placing new node as LRU tail */ 
    fp->lru_prev = lru_list.last;
    lru_list.last = fp;
  }

  fp->deadline = time(NULL)+IPF_TIMEOUT;
  fp->ip_id = iphp->ip_id;
  fp->ip_p = iphp->ip_p;
  fp->ip_src = iphp->ip_src.s_addr;
  fp->ip_dst = iphp->ip_dst.s_addr;
  fp->bucket = bucket;

  if (!(iphp->ip_off & htons(IP_OFFMASK))) {
    /* it's a first fragment */
    fp->got_first = TRUE;
    memcpy(fp->tlhdr, pptrs->tlh_ptr, sizeof(struct my_tlhdr));
    return TRUE;
  }
  else {
    /* not a first fragment; increase accumulator */
    fp->a = ntohs(iphp->ip_len); 
    return FALSE;
  }
}

void prune_old_fragments(u_int32_t off)
{
  struct ip_fragment *fp, *temp;
  u_int32_t deadline = time(NULL)-off;

  fp = lru_list.root->lru_next;
  while (fp) {
    if (deadline > fp->deadline) {
      /* we found a stale element; we'll prune it */
      if (fp->lru_next) temp = fp->lru_next;
      else temp = NULL;

      /* rearranging bucket's pointers */ 
      if (fp->prev && fp->next) {
	fp->prev->next = fp->next;
        fp->next->prev = fp->prev;
      }
      else if (fp->prev) fp->prev->next = NULL;
      else if (fp->next) {
	ipft[fp->bucket] = fp->next;
	fp->next->prev = NULL; 
      }
      else ipft[fp->bucket] = NULL;

      free(fp);
      ipft_total_nodes--;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else break;
  }

  if (fp) {
    fp->lru_prev = lru_list.root;
    lru_list.root->lru_next = fp;
  }
  else lru_list.last = lru_list.root;

  // printf("PRUNE -- nodes: %d\n", ipft_total_nodes);
  // count = 0;
}

/* hash_fragment() is taken (it has another name there) from Linux kernel 2.4;
   see full credits contained in jhash.h */ 
unsigned int hash_fragment(u_int16_t id, u_int32_t src, u_int32_t dst, u_int8_t proto)
{
  return jhash_3words((u_int32_t)id << 16 | proto, src, dst, trivial_hash_rnd) & (IPFT_HASHSZ-1);
}
