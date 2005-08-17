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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __IP_FLOW_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "jhash.h"
#include "util.h"

u_int32_t flt_total_nodes;  
time_t flt_prune_deadline;
time_t flt_emergency_prune;
time_t flow_generic_lifetime;
u_int32_t flt_trivial_hash_rnd = 140281; /* ummmh */

#if defined ENABLE_IPV6
u_int32_t flt6_total_nodes;
time_t flt6_prune_deadline;
time_t flt6_emergency_prune;
#endif

void init_ip_flow_handler()
{
  init_ip4_flow_handler();
#if defined ENABLE_IPV6
  init_ip6_flow_handler();
#endif
}

void init_ip4_flow_handler()
{
  if (config.flow_bufsz) flt_total_nodes = config.flow_bufsz / sizeof(struct ip_flow);
  else flt_total_nodes = DEFAULT_FLOW_BUFFER_SIZE / sizeof(struct ip_flow); 

  memset(ip_flow_table, 0, sizeof(ip_flow_table));
  flow_lru_list.root = (struct ip_flow *) malloc(sizeof(struct ip_flow)); 
  flow_lru_list.last = flow_lru_list.root;
  memset(flow_lru_list.root, 0, sizeof(struct ip_flow));
  flt_prune_deadline = time(NULL)+FLOW_TABLE_PRUNE_INTERVAL;
  flt_emergency_prune = 0; 
  if (config.flow_lifetime) flow_generic_lifetime = config.flow_lifetime;
  else flow_generic_lifetime = FLOW_GENERIC_LIFETIME; 
}

int ip_flow_handler(struct packet_ptrs *pptrs)
{
  time_t now = time(NULL);

  if (now > flt_prune_deadline) {
    prune_old_flows(now);
    flt_prune_deadline = now+FLOW_TABLE_PRUNE_INTERVAL;
  }
  return find_flow(now, pptrs);
}

Inline void is_closing(u_int32_t now, struct packet_ptrs *pptrs, struct ip_flow_common *fp)
{
  if (pptrs->is_closing) fp->closed = now;
  else fp->closed = FALSE;
  fp->ctype = pptrs->is_closing;
}

int find_flow(u_int32_t now, struct packet_ptrs *pptrs)
{
  struct my_iphdr *iphp = (struct my_iphdr *)pptrs->iph_ptr;
  struct my_tlhdr *tlhp = (struct my_tlhdr *)pptrs->tlh_ptr;
  struct ip_flow *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int bucket = hash_flow(iphp->ip_src.s_addr, iphp->ip_dst.s_addr,
				      tlhp->src_port, tlhp->dst_port, iphp->ip_p);

  for (fp = ip_flow_table[bucket]; fp; fp = fp->next) {
    if (fp->ip_src == iphp->ip_src.s_addr && fp->ip_dst == iphp->ip_dst.s_addr &&
	fp->port_src == tlhp->src_port && fp->port_dst == tlhp->dst_port &&
	fp->cmn.proto == iphp->ip_p) {
      /* flow found; will check for its lifetime */
      if (!is_expired(now, &fp->cmn)) {
	/* still valid flow */ 
	if (!fp->cmn.closed) is_closing(now, pptrs, &fp->cmn);
	fp->cmn.last = now;
	return FALSE; 
      }
      else {
	/* stale flow: will start a new one */ 
	is_closing(now, pptrs, &fp->cmn);
	fp->cmn.last = now;
	return TRUE;
      } 
    }
    if (!candidate && is_expired(now, &fp->cmn)) candidate = fp; 
    last_seen = fp;
  } 

  create:
  if (candidate) return create_flow(now, candidate, TRUE, bucket, pptrs);
  else return create_flow(now, last_seen, FALSE, bucket, pptrs); 
}

int create_flow(u_int32_t now, struct ip_flow *fp, u_int8_t is_candidate, unsigned int bucket, struct packet_ptrs *pptrs)
{
  struct my_iphdr *iphp = (struct my_iphdr *)pptrs->iph_ptr;
  struct my_tlhdr *tlhp = (struct my_tlhdr *)pptrs->tlh_ptr;
  struct ip_flow *newf;

  if (!flt_total_nodes) {
    if (now > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer full. Skipping flows.\n"); 
      flt_emergency_prune = now;
      prune_old_flows(now);
    }
    return FALSE; 
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) { 
      newf = (struct ip_flow *) malloc(sizeof(struct ip_flow));
      if (!newf) { 
	if (now > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer finished memory. Skipping flows.\n");
	  flt_emergency_prune = now;
	  prune_old_flows(now);
	}
	return FALSE;
      }
      else flt_total_nodes--;
      memset(newf, 0, sizeof(struct ip_flow));
      fp->next = newf;
      newf->prev = fp;  
      flow_lru_list.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = flow_lru_list.last;
      flow_lru_list.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */ 
        fp->lru_prev->lru_next = fp->lru_next; 
	fp->lru_next->lru_prev = fp->lru_prev;
	flow_lru_list.last->lru_next = fp;
	fp->lru_prev = flow_lru_list.last;
	fp->lru_next = NULL;
	flow_lru_list.last = fp;
      }
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */ 
    fp = (struct ip_flow *) malloc(sizeof(struct ip_flow));  
    if (!fp) {
      if (now > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer finished memory. Skipping flows.\n");
        flt_emergency_prune = now;
        prune_old_flows(now);
      }
      return FALSE;
    }
    else flt_total_nodes--;
    memset(fp, 0, sizeof(struct ip_flow));
    ip_flow_table[bucket] = fp;
    flow_lru_list.last->lru_next = fp; /* placing new node as LRU tail */ 
    fp->lru_prev = flow_lru_list.last;
    flow_lru_list.last = fp;
  }

  is_closing(now, pptrs, &fp->cmn); 
  fp->ip_src = iphp->ip_src.s_addr;
  fp->ip_dst = iphp->ip_dst.s_addr;
  fp->port_src = tlhp->src_port;
  fp->port_dst = tlhp->dst_port;
  fp->cmn.last = now; 
  fp->cmn.proto = iphp->ip_p;
  fp->cmn.bucket = bucket;

  return TRUE;
}

void prune_old_flows(u_int32_t now)
{
  struct ip_flow *fp, *temp;

  fp = flow_lru_list.root->lru_next;
  while (fp) {
    if (is_expired(now, &fp->cmn)) {
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
	ip_flow_table[fp->cmn.bucket] = fp->next;
	fp->next->prev = NULL; 
      }
      else ip_flow_table[fp->cmn.bucket] = NULL;

      free(fp);
      flt_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else break;
  }

  if (fp) {
    fp->lru_prev = flow_lru_list.root;
    flow_lru_list.root->lru_next = fp;
  }
  else flow_lru_list.last = flow_lru_list.root;
}

/* hash_fragment() is taken (it has another name there) from Linux kernel 2.4;
   see full credits contained in jhash.h */ 
Inline unsigned int hash_flow(u_int32_t ip_src, u_int32_t ip_dst,
		u_int16_t port_src, u_int16_t port_dst, u_int8_t proto)
{
  return jhash_3words((u_int32_t)(port_src ^ port_dst) << 16 | proto, ip_src, ip_dst, flt_trivial_hash_rnd) & (FLOW_TABLE_HASHSZ-1);
}

/* is_expired() returns: TRUE if the flow has expired; FALSE if the flow
   is still valid; the function will contain any further semi-stateful
   evaluation over specific protocols */ 
Inline unsigned int is_expired(u_int32_t now, struct ip_flow_common *fp)
{
  if (fp->proto == IPPROTO_TCP && fp->closed) {
    if ((fp->ctype == FL_TCPFIN) && (now > fp->closed+FLOW_TCPFIN_LIFETIME)) return TRUE;
    if (fp->ctype == FL_TCPRST) return TRUE;
  }

  if (now < fp->last+flow_generic_lifetime) return FALSE;
  else return TRUE;
}

#if defined ENABLE_IPV6
void init_ip6_flow_handler()
{
  if (config.frag_bufsz) flt6_total_nodes = config.frag_bufsz / sizeof(struct ip_flow6);
  else flt6_total_nodes = DEFAULT_FLOW_BUFFER_SIZE / sizeof(struct ip_flow6);

  memset(ip_flow_table6, 0, sizeof(ip_flow_table6));
  flow_lru_list6.root = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
  flow_lru_list6.last = flow_lru_list6.root;
  memset(flow_lru_list6.root, 0, sizeof(struct ip_flow6));
  flt6_prune_deadline = time(NULL)+FLOW_TABLE_PRUNE_INTERVAL;
  flt6_emergency_prune = 0;
  if (config.flow_lifetime) flow_generic_lifetime = config.flow_lifetime;
  else flow_generic_lifetime = FLOW_GENERIC_LIFETIME;
}

int ip_flow6_handler(struct packet_ptrs *pptrs)
{
  time_t now = time(NULL);

  if (now > flt6_prune_deadline) {
    prune_old_flows6(now);
    flt6_prune_deadline = now+FLOW_TABLE_PRUNE_INTERVAL;
  }
  return find_flow6(now, pptrs);
}

unsigned int hash_flow6(u_int32_t id, struct in6_addr *saddr, struct in6_addr *daddr)
{
        u_int32_t a, b, c;
	u_int32_t *src = (u_int32_t *)saddr, *dst = (u_int32_t *)daddr;

        a = src[0];
        b = src[1];
        c = src[2];

        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += flt_trivial_hash_rnd;
        __jhash_mix(a, b, c);

        a += src[3];
        b += dst[0];
        c += dst[1];
        __jhash_mix(a, b, c);

        a += dst[2];
        b += dst[3];
        c += id;
        __jhash_mix(a, b, c);

        return c & (FLOW_TABLE_HASHSZ - 1);
}

int find_flow6(u_int32_t now, struct packet_ptrs *pptrs)
{
  struct ip6_hdr *iphp = (struct ip6_hdr *)pptrs->iph_ptr;
  struct my_tlhdr *tlhp = (struct my_tlhdr *)pptrs->tlh_ptr;
  struct ip_flow6 *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int bucket = hash_flow6((tlhp->src_port << 16) | tlhp->dst_port, &iphp->ip6_src, &iphp->ip6_dst); 

  for (fp = ip_flow_table6[bucket]; fp; fp = fp->next) {
    if (!ip6_addr_cmp(&fp->ip_src, &iphp->ip6_src) && !ip6_addr_cmp(&fp->ip_dst, &iphp->ip6_dst) &&
        fp->port_src == tlhp->src_port && fp->port_dst == tlhp->dst_port &&
	fp->cmn.proto == pptrs->l4_proto) {
      /* flow found; will check for its lifetime */
      if (!is_expired(now, &fp->cmn)) {
        /* still valid flow */
	if (!fp->cmn.closed) is_closing(now, pptrs, &fp->cmn);
	fp->cmn.last = now;
	return FALSE;
      }
      else {
        /* stale flow: will start a new one */
	is_closing(now, pptrs, &fp->cmn);
	fp->cmn.last = now;
	return TRUE;
      }
    }
    if (!candidate && is_expired(now, &fp->cmn)) candidate = fp;
    last_seen = fp;
  }

  create:
  if (candidate) return create_flow6(now, candidate, TRUE, bucket, pptrs);
  else return create_flow6(now, last_seen, FALSE, bucket, pptrs);
}

int create_flow6(u_int32_t now, struct ip_flow6 *fp, u_int8_t is_candidate, unsigned int bucket,
			struct packet_ptrs *pptrs)
{
  struct ip6_hdr *iphp = (struct ip6_hdr *)pptrs->iph_ptr;
  struct my_tlhdr *tlhp = (struct my_tlhdr *)pptrs->tlh_ptr;
  struct ip_flow6 *newf;

  if (!flt6_total_nodes) {
    if (now > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
      flt6_emergency_prune = now;
      prune_old_flows6(now);
    }
    return FALSE;
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) {
      newf = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
      if (!newf) {
	if (now > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
	  flt6_emergency_prune = now;
	  prune_old_flows6(now);
	}
        return FALSE;
      }
      else flt6_total_nodes--;
      memset(newf, 0, sizeof(struct ip_flow6));
      fp->next = newf;
      newf->prev = fp;
      flow_lru_list6.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = flow_lru_list6.last;
      flow_lru_list6.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */
        fp->lru_prev->lru_next = fp->lru_next;
        fp->lru_next->lru_prev = fp->lru_prev;
        flow_lru_list6.last->lru_next = fp;
        fp->lru_prev = flow_lru_list6.last;
        fp->lru_next = NULL;
        flow_lru_list6.last = fp;
      }
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */
    fp = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
    if (!fp) {
      if (now > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
        flt6_emergency_prune = now;
        prune_old_flows6(now);
      }
      return FALSE;
    }
    else flt6_total_nodes--;
    memset(fp, 0, sizeof(struct ip_flow6));
    ip_flow_table6[bucket] = fp;
    flow_lru_list6.last->lru_next = fp; /* placing new node as LRU tail */
    fp->lru_prev = flow_lru_list6.last;
    flow_lru_list6.last = fp;
  }

  is_closing(now, pptrs, &fp->cmn);
  ip6_addr_cpy(&fp->ip_src, &iphp->ip6_src);
  ip6_addr_cpy(&fp->ip_dst, &iphp->ip6_dst);
  fp->port_src = tlhp->src_port;
  fp->port_dst = tlhp->dst_port;
  fp->cmn.last = now;
  fp->cmn.proto = pptrs->l4_proto;
  fp->cmn.bucket = bucket;

  return TRUE;
}

void prune_old_flows6(u_int32_t now)
{
  struct ip_flow6 *fp, *temp;

  fp = flow_lru_list6.root->lru_next;
  while (fp) {
    if (is_expired(now, &fp->cmn)) {
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
        ip_flow_table6[fp->cmn.bucket] = fp->next;
        fp->next->prev = NULL;
      }
      else ip_flow_table6[fp->cmn.bucket] = NULL;

      free(fp);
      flt6_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else break;
  }

  if (fp) {
    fp->lru_prev = flow_lru_list6.root;
    flow_lru_list6.root->lru_next = fp;
  }
  else flow_lru_list6.last = flow_lru_list6.root;
}
#endif
