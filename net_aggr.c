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

#define __NET_AGGR_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "net_aggr.h"
#include "util.h"
#include "jhash.h"

void load_networks(char *filename, struct networks_table *nt, struct networks_cache *nc)
{
  load_networks4(filename, nt, nc);
#if defined ENABLE_IPV6
  load_networks6(filename, nt, nc);
#endif
}

void load_networks4(char *filename, struct networks_table *nt, struct networks_cache *nc)
{
  FILE *file;
  struct networks_table tmp, *tmpt = &tmp; 
  struct networks_table_metadata *mdt;
  char buf[SRVBUFLEN], *bufptr, *delim, *as, *net, *mask;
  int rows, eff_rows = 0, j, buflen;
  unsigned int index;

  nt->table = 0;
  nt->num = 0;
  nc->cache = 0;
  nc->num = 0;
  memset(&dummy_entry, 0, sizeof(struct networks_table_entry));

  if (filename) {
    if ((file = fopen(filename,"r")) == NULL) {
      if ((config.acct_type == ACCT_NF) && (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS)) &&
	  (!(config.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET))) && (config.nfacctd_as == NF_AS_KEEP))
	return;

      Log(LOG_ERR, "ERROR: network file '%s' not found\n", filename);
      exit(1); 
    }
    else {
      rows = 0;
      /* 1st step: count rows for table allocation */
      while (!feof(file)) {
        if (fgets(buf, SRVBUFLEN, file)) rows++; 
      }
      /* 2nd step: loading data into a temporary table */
      freopen(filename, "r", file);
      nt->table = malloc(rows*sizeof(struct networks_table_entry)); 
      tmpt->table = malloc(rows*sizeof(struct networks_table_entry));
      memset(nt->table, 0, rows*sizeof(struct networks_table_entry));
      memset(tmpt->table, 0, rows*sizeof(struct networks_table_entry));
      rows = 1;
      while (!feof(file)) {
	bufptr = buf;
	memset(buf, 0, SRVBUFLEN);
        if (fgets(buf, SRVBUFLEN, file)) { 
	  if (delim = strchr(buf, ',')) {
	    as = buf;
	    *delim = '\0';
	    bufptr = delim+1;
	    tmpt->table[eff_rows].as = atoi(as);
	  }
	  else tmpt->table[eff_rows].as = 0;
	  if (!sanitize_buf_net(filename, bufptr, rows)) {
	    delim = strchr(bufptr, '/');
	    *delim = '\0';
	    net = bufptr;
	    mask = delim+1;

            if (!inet_aton(net, (struct in_addr *) &tmpt->table[eff_rows].net)) goto cycle_end;

	    buflen = strlen(mask);
	    for (j = 0; j < buflen; j++) {
	      if (!isdigit(mask[j])) {
		Log(LOG_ERR, "ERROR ( %s ): Invalid network mask '%s'.\n", filename, mask);
		goto cycle_end;
	      }
	    }
	    index = atoi(mask); 
	    if (index > 32) {
	      Log(LOG_ERR, "ERROR ( %s ): Invalid network mask '%d'.\n", filename, index);
	      goto cycle_end;
	    }

	    tmpt->table[eff_rows].net = ntohl(tmpt->table[eff_rows].net);
	    tmpt->table[eff_rows].mask = (index == 32) ? 0xffffffffUL : ~(0xffffffffUL >> index);
	    tmpt->table[eff_rows].net &= tmpt->table[eff_rows].mask; /* enforcing mask on given network */

	    eff_rows++;
	  } 
	}
	cycle_end:
	rows++;
      }
      fclose(file);

      /* 3rd step: sorting table */
      merge_sort(filename, tmpt->table, 0, eff_rows);
      tmpt->num = eff_rows;

      /* 4th step: collecting informations in the sorted table;
         we wish to handle networks-in-networks hierarchically */

      /* 4a building hierarchies */
      mdt = malloc(tmpt->num*sizeof(struct networks_table_metadata));
      memset(mdt, 0, tmpt->num*sizeof(struct networks_table_metadata));

      if (tmpt->num) {
        for (index = 0; index < (tmpt->num-1); index++) {
	  u_int32_t net;
	  int x;

	  for (x = index+1; x < tmpt->num; x++) {
	    net = tmpt->table[x].net;
	    net &= tmpt->table[index].mask;
	    if (net == tmpt->table[index].net) {
	      mdt[x].level++;
	      mdt[index].childs++; 
	    }
	    else break;
	  }
        } 
      }

      /* 4b retrieving root entries number */
      for (index = 0, eff_rows = 0; index < tmpt->num; index++) {
        if (mdt[index].level == 0) eff_rows++;
      }

      nt->num = eff_rows;
      /* 4c adjusting child counters: each parent has to know
         only the number of its directly attached childs and
	 not the whole hierarchy */ 
      for (index = 0; index < tmpt->num; index++) {
        int x, eff_childs = 0;

        for (x = index+1; x < tmpt->num; x++) {
	  if (mdt[index].level == mdt[x].level) break;
	  else if (mdt[index].level == (mdt[x].level-1)) eff_childs++; 
	}
	mdt[index].childs = eff_childs;
      }

      /* 5th step: building final networks table */
      for (index = 0; index < tmpt->num; index++) {
	int current, next, prev[128];

        if (!index) {
	  current = 0; next = eff_rows;
	  memset(&prev, 0, 32);
	  memcpy(&nt->table[current], &tmpt->table[index], sizeof(struct networks_table_entry));
        }
	else {
	  if (mdt[index].level == mdt[index-1].level) current++; /* do nothing: we have only to copy our element */ 
	  else if (mdt[index].level > mdt[index-1].level) { /* we encountered a child */ 
	    nt->table[current].childs_table.table = &nt->table[next];
	    nt->table[current].childs_table.num = mdt[index-1].childs;
	    prev[mdt[index-1].level] = current;
	    current = next;
	    next += mdt[index-1].childs;
	  }
	  else { /* going back to parent level */
	    current = prev[mdt[index].level];
	    current++;
	  }
	  memcpy(&nt->table[current], &tmpt->table[index], sizeof(struct networks_table_entry));
        }
      }

      if (config.debug) { 
        index = 0;
        while (index < tmpt->num) {
	  Log(LOG_DEBUG, "DEBUG ( %s ): (networks table IPv4) net: %x, mask: %x\n", 
			  filename, nt->table[index].net, nt->table[index].mask); 
	  // Log(LOG_DEBUG, "DEBUG: (networks table) net: %x, mask: %x, level: %u, childs: %u\n",
	  //   tmpt->table[index].net, tmpt->table[index].mask, mdt[index].level, mdt[index].childs); 
	  index++;
	}
      }

      /* create networks cache */
      if (!config.networks_cache_entries) nc->num = NETWORKS_CACHE_ENTRIES;
      else nc->num = config.networks_cache_entries;
      nc->cache = (struct networks_cache_entry *) malloc(nc->num*sizeof(struct networks_cache_entry));
      memset(nc->cache, 0, nc->num*sizeof(struct networks_cache_entry));
    }
  }
}

/* sort the (sub)array v from start to end */
void merge_sort(char *filename, struct networks_table_entry *table, int start, int end)
{
  int middle;

  /* no elements to sort */
  if ((start == end) || (start == end-1)) return;

  /* find the middle of the array, splitting it into two subarrays */
  middle = (start+end)/2;

  /* sort the subarray from start..middle */
  merge_sort(filename, table, start, middle);

  /* sort the subarray from middle..end */
  merge_sort(filename, table, middle, end);

  /* merge the two sorted halves */
  merge(filename, table, start, middle, end);
}

/* 
   merge the subarray v[start..middle] with v[middle..end], placing the
   result back into v.
*/
void merge(char *filename, struct networks_table_entry *table, int start, int middle, int end)
{
  struct networks_table_entry *v1, *v2;
  int  v1_n, v2_n, v1_index, v2_index, i, s = sizeof(struct networks_table_entry);

  v1_n = middle-start;
  v2_n = end-middle;

  v1 = malloc(v1_n*s);
  v2 = malloc(v2_n*s);

  if ((!v1) || (!v2)) Log(LOG_ERR, "ERROR ( %s ): Memory sold out when allocating 'networks table'\n", filename); 

  for (i=0; i<v1_n; i++) memcpy(&v1[i], &table[start+i], s);
  for (i=0; i<v2_n; i++) memcpy(&v2[i], &table[middle+i], s);

  v1_index = 0;
  v2_index = 0;

  /* as we pick elements from one or the other to place back into the table */
  for (i=0; (v1_index < v1_n) && (v2_index < v2_n); i++) {
    /* current v1 element less than current v2 element? */
    if (v1[v1_index].net < v2[v2_index].net) memcpy(&table[start+i], &v1[v1_index++], s);
    else if (v1[v1_index].net == v2[v2_index].net) {
      if (v1[v1_index].mask <= v2[v2_index].mask) memcpy(&table[start+i], &v1[v1_index++], s);
      else memcpy(&table[start+i], &v2[v2_index++], s);
    }
    else memcpy(&table[start+i], &v2[v2_index++], s); 
  }

  /* clean up; either v1 or v2 may have stuff left in it */
  for (; v1_index < v1_n; i++) memcpy(&table[start+i], &v1[v1_index++], s);
  for (; v2_index < v2_n; i++) memcpy(&table[start+i], &v2[v2_index++], s);

  free(v1);
  free(v2);
}

struct networks_table_entry *binsearch(struct networks_table *nt, struct networks_cache *nc, struct host_addr *a)
{
  int low = 0, mid, high = nt->num-1;
  u_int32_t net, addrh = ntohl(a->address.ipv4.s_addr), addr = a->address.ipv4.s_addr;
  struct networks_table_entry *ret;

  ret = networks_cache_search(nc, &addr); 
  if (ret) return ret;

  while (low <= high) {
    mid = (low+high)/2;
    net = addrh;
    net &= nt->table[mid].mask;

    if (net < nt->table[mid].net) {
      high = mid-1;
      continue;
    }
    else if (net > nt->table[mid].net) {
      low = mid+1;
      continue;
    }

    /* It's assumed we've found our element */
    if (nt->table[mid].childs_table.table) {
      ret = binsearch(&nt->table[mid].childs_table, nc, a);
      if (!ret) {
	ret = &nt->table[mid];
        networks_cache_insert(nc, &addr, &nt->table[mid]);
      }
    }
    else {
      ret = &nt->table[mid];
      networks_cache_insert(nc, &addr, &nt->table[mid]);
    }
    return ret;
  }

  networks_cache_insert(nc, &addr, &dummy_entry);
  return NULL;
}

void networks_cache_insert(struct networks_cache *nc, u_int32_t *key, struct networks_table_entry *result)
{
  struct networks_cache_entry *ptr;

  ptr = &nc->cache[*key % nc->num];
  ptr->key = *key;
  ptr->result = result;
}

struct networks_table_entry *networks_cache_search(struct networks_cache *nc, u_int32_t *key)
{
  struct networks_cache_entry *ptr;

  ptr = &nc->cache[*key % nc->num];
  if (ptr->key == *key) return ptr->result;
  else return NULL;
}

void set_net_funcs(struct networks_table *nt)
{
  u_int8_t count = 0;

  memset(&net_funcs, 0, sizeof(net_funcs));

#if defined ENABLE_IPV6
  if ((!nt->num) && (!nt->num6)) return;
#else
  if (!nt->num) return;
#endif

  if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    net_funcs[count] = search_src_host;
    count++;
  }

  if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
    net_funcs[count] = search_src_net;
    count++;
  } 

  if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    if ((config.acct_type == ACCT_NF) && (config.nfacctd_as == NF_AS_KEEP));
    else {
      net_funcs[count] = search_src_as;
      count++;
    }
  }

  if (config.what_to_count & (COUNT_DST_HOST|COUNT_SUM_HOST)) {
    net_funcs[count] = search_dst_host;
    count++;
  }

  if (config.what_to_count & (COUNT_DST_NET|COUNT_SUM_NET)) {
    net_funcs[count] = search_dst_net;
    count++;
  }

  if (config.what_to_count & (COUNT_DST_AS|COUNT_SUM_AS)) {
    if ((config.acct_type == ACCT_NF) && (config.nfacctd_as == NF_AS_KEEP));
    else {
      net_funcs[count] = search_dst_as;
      count++;
    }
  }
}

void search_src_host(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif

  if (p->src_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->src_ip);
    if (!res) p->src_ip.address.ipv4.s_addr = 0;
    else if (!res->net) p->src_ip.address.ipv4.s_addr = 0; /* it may have been cached */
  }
#if defined ENABLE_IPV6
  else if (p->src_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->src_ip);
    if (!res6) memset(&p->src_ip.address.ipv6, 0, IP6AddrSz);
    else if (!res6->net[0]) memset(&p->src_ip.address.ipv6, 0, IP6AddrSz); /* it may have been cached */
  }
#endif
}

void search_dst_host(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif

  if (p->dst_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->dst_ip);
    if (!res) p->dst_ip.address.ipv4.s_addr = 0;
    else if (!res->net) p->dst_ip.address.ipv4.s_addr = 0; /* it may have been cached */
  }
#if defined ENABLE_IPV6
  else if (p->dst_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->dst_ip);
    if (!res6) memset(&p->dst_ip.address.ipv6, 0, IP6AddrSz);
    else if (!res6->net[0]) memset(&p->dst_ip.address.ipv6, 0, IP6AddrSz); /* it may have been cached */
  }
#endif
}

void search_src_net(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif

  if (p->src_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->src_ip);
    if (!res) p->src_ip.address.ipv4.s_addr = 0;
    else p->src_ip.address.ipv4.s_addr = htonl(res->net);
  }
#if defined ENABLE_IPV6
  else if (p->src_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->src_ip);
    if (!res6) memset(&p->src_ip.address.ipv6, 0, IP6AddrSz);
    else memcpy(&p->src_ip.address.ipv6, (void *)pm_htonl6(res6->net), IP6AddrSz); /* it may have been cached */
  }
#endif
}

void search_dst_net(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif
  
  if (p->dst_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->dst_ip);
    if (!res) p->dst_ip.address.ipv4.s_addr = 0;
    else p->dst_ip.address.ipv4.s_addr = htonl(res->net);
  }
#if defined ENABLE_IPV6
  else if (p->dst_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->dst_ip);
    if (!res6) memset(&p->dst_ip.address.ipv6, 0, IP6AddrSz);
    else memcpy(&p->dst_ip.address.ipv6, (void *)pm_htonl6(res6->net), IP6AddrSz); /* it may have been cached */
  }
#endif
}

void search_src_as(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif
  
  if (p->src_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->src_ip);
    if (!res) p->src_ip.address.ipv4.s_addr = 0;
    else p->src_ip.address.ipv4.s_addr = htonl(res->as);
  }
#if defined ENABLE_IPV6
  else if (p->src_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->src_ip);
    if (!res6) memset(&p->src_ip.address.ipv6, 0, IP6AddrSz);
    else {
      p->src_ip.family = AF_INET;
      p->src_ip.address.ipv4.s_addr = htonl(res6->as);
    }
  }
#endif
}

void search_dst_as(struct networks_table *nt, struct networks_cache *nc, struct pkt_primitives *p)
{
  struct networks_table_entry *res;
#if defined ENABLE_IPV6
  struct networks6_table_entry *res6;
#endif
  
  if (p->dst_ip.family == AF_INET) {
    res = binsearch(nt, nc, &p->dst_ip);
    if (!res) p->dst_ip.address.ipv4.s_addr = 0;
    else p->dst_ip.address.ipv4.s_addr = htonl(res->as);
  }
#if defined ENABLE_IPV6
  else if (p->dst_ip.family == AF_INET6) {
    res6 = binsearch6(nt, nc, &p->dst_ip);
    if (!res6) memset(&p->dst_ip.address.ipv6, 0, IP6AddrSz);
    else {
      p->dst_ip.family = AF_INET;
      p->dst_ip.address.ipv4.s_addr = htonl(res6->as);
    }
  }
#endif
}

#if defined ENABLE_IPV6
void load_networks6(char *filename, struct networks_table *nt, struct networks_cache *nc)
{
  FILE *file;
  struct networks_table tmp, *tmpt = &tmp;
  struct networks_table_metadata *mdt;
  char buf[SRVBUFLEN], *bufptr, *delim, *as, *net, *mask;
  int rows, eff_rows = 0, j, buflen;
  unsigned int index;
  u_int32_t tmpmask[4], tmpnet[4];

  nt->table6 = 0;
  nt->num6 = 0;
  nc->cache6 = 0;
  nc->num6 = 0;
  memset(&dummy_entry6, 0, sizeof(struct networks6_table_entry));

  if (filename) {
    if ((file = fopen(filename,"r")) == NULL) {
      if ((config.acct_type == ACCT_NF) && (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS)) &&
          (!(config.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET))) && (config.nfacctd_as == NF_AS_KEEP))
        return;

      Log(LOG_ERR, "ERROR: network file '%s' not found\n", filename);
      exit(1);
    }
    else {
      rows = 0;
      /* 1st step: count rows for table allocation */
      while (!feof(file)) {
        if (fgets(buf, SRVBUFLEN, file)) rows++;
      }
      /* 2nd step: loading data into a temporary table */
      freopen(filename, "r", file);
      nt->table6 = malloc(rows*sizeof(struct networks6_table_entry));
      tmpt->table6 = malloc(rows*sizeof(struct networks6_table_entry));
      memset(nt->table6, 0, rows*sizeof(struct networks6_table_entry));
      memset(tmpt->table6, 0, rows*sizeof(struct networks6_table_entry));
      rows = 1;
      while (!feof(file)) {
        bufptr = buf;
        memset(buf, 0, SRVBUFLEN);
        if (fgets(buf, SRVBUFLEN, file)) {
          if (delim = strchr(buf, ',')) {
            as = buf;
            *delim = '\0';
            bufptr = delim+1;
            tmpt->table6[eff_rows].as = atoi(as);
          }
          else tmpt->table6[eff_rows].as = 0;
          if (!sanitize_buf_net(filename, bufptr, rows)) {
            delim = strchr(bufptr, '/');
            *delim = '\0';
            net = bufptr;
            mask = delim+1;

	    /* XXX: error signallation */
            if (!inet_pton(AF_INET6, net, &tmpnet)) goto cycle_end;

            buflen = strlen(mask);
            for (j = 0; j < buflen; j++) {
              if (!isdigit(mask[j])) {
                Log(LOG_ERR, "ERROR ( %s ): Invalid network mask '%s'.\n", filename, mask);
                goto cycle_end;
              }
            }
            index = atoi(mask);
            if (index > 128) {
              Log(LOG_ERR, "ERROR ( %s ): Invalid network mask '%d'.\n", filename, index);
              goto cycle_end;
            }

	    for (j = 0; j < 4 && index >= 32; j++, index -= 32) tmpmask[j] = 0xffffffffU; 
	    if (j < 4 && index) tmpmask[j] = ~(0xffffffffU >> index);
            for (j = 0; j < 4; j++) tmpnet[j] = ntohl(tmpnet[j]);
	    for (j = 0; j < 4; j++) tmpnet[j] &= tmpmask[j]; /* enforcing mask on given network */ 

            memcpy(&tmpt->table6[eff_rows].net, tmpnet, IP6AddrSz);
            memcpy(&tmpt->table6[eff_rows].mask, tmpmask, IP6AddrSz);


            eff_rows++;
          }
        }
        cycle_end:
        rows++;
      }
      fclose(file);

      /* 3rd step: sorting table */
      merge_sort6(filename, tmpt->table6, 0, eff_rows);
      tmpt->num6 = eff_rows;

      /* 4th step: collecting informations in the sorted table;
         we wish to handle networks-in-networks hierarchically */

      /* 4a building hierarchies */
      mdt = malloc(tmpt->num6*sizeof(struct networks_table_metadata));
      memset(mdt, 0, tmpt->num6*sizeof(struct networks_table_metadata));

      if (tmpt->num6) {
        for (index = 0; index < (tmpt->num6-1); index++) {
          u_int32_t net[4];
          int x, chunk;

          for (x = index+1; x < tmpt->num6; x++) {
            memcpy(&net, &tmpt->table6[x].net, IP6AddrSz);
            for (chunk = 0; chunk < 4; chunk++) net[chunk] &= tmpt->table6[index].mask[chunk];
            for (chunk = 0; chunk < 4; chunk++) {
	      if (net[chunk] == tmpt->table6[index].net[chunk]) {
                if (chunk == 3) {
		  mdt[x].level++;
		  mdt[index].childs++;
	        }
              }
              else break;
            }
          }
        }
      }

      /* 4b retrieving root entries number */
      for (index = 0, eff_rows = 0; index < tmpt->num6; index++) {
        if (mdt[index].level == 0) eff_rows++;
      }

      nt->num6 = eff_rows;
      /* 4c adjusting child counters: each parent has to know
         only the number of its directly attached childs and
         not the whole hierarchy */
      for (index = 0; index < tmpt->num6; index++) {
        int x, eff_childs = 0;

        for (x = index+1; x < tmpt->num6; x++) {
          if (mdt[index].level == mdt[x].level) break;
          else if (mdt[index].level == (mdt[x].level-1)) eff_childs++;
        }
        mdt[index].childs = eff_childs;
      }

      /* 5th step: building final networks table */
      for (index = 0; index < tmpt->num6; index++) {
        int current, next, prev[128];

        if (!index) {
          current = 0; next = eff_rows;
          memset(&prev, 0, 32);
          memcpy(&nt->table6[current], &tmpt->table6[index], sizeof(struct networks6_table_entry));
        }
        else {
          if (mdt[index].level == mdt[index-1].level) current++; /* do nothing: we have only to copy our element */
          else if (mdt[index].level > mdt[index-1].level) { /* we encountered a child */
            nt->table6[current].childs_table.table6 = &nt->table6[next];
            nt->table6[current].childs_table.num6 = mdt[index-1].childs;
            prev[mdt[index-1].level] = current;
            current = next;
            next += mdt[index-1].childs;
          }
          else { /* going back to parent level */
            current = prev[mdt[index].level];
            current++;
          }
          memcpy(&nt->table6[current], &tmpt->table6[index], sizeof(struct networks6_table_entry));
        }
      }

      if (config.debug) {
        index = 0;
        while (index < tmpt->num6) {
          Log(LOG_DEBUG, "DEBUG ( %s ): (networks table IPv6) net: %x:%x:%x:%x, mask: %x:%x:%x:%x\n", filename,
	    nt->table6[index].net[0], nt->table6[index].net[1], nt->table6[index].net[2], nt->table6[index].net[3],
	    nt->table6[index].mask[0], nt->table6[index].mask[1], nt->table6[index].mask[2], nt->table6[index].mask[3]);
          // Log(LOG_DEBUG, "DEBUG: (networks table) net: %x, mask: %x, level: %u, childs: %u\n",
          //   tmpt->table[index].net, tmpt->table[index].mask, mdt[index].level, mdt[index].childs);
          index++;
        }
      }

      /* create networks cache */
      if (!config.networks_cache_entries) nc->num6 = NETWORKS6_CACHE_ENTRIES;
      else nc->num6 = config.networks_cache_entries;
      nc->cache6 = (struct networks6_cache_entry *) malloc(nc->num6*sizeof(struct networks6_cache_entry));
      memset(nc->cache6, 0, nc->num6*sizeof(struct networks6_cache_entry));
    }
  }
}

/* sort the (sub)array v from start to end */
void merge_sort6(char * filename, struct networks6_table_entry *table, int start, int end)
{
  int middle;

  /* no elements to sort */
  if ((start == end) || (start == end-1)) return;

  /* find the middle of the array, splitting it into two subarrays */
  middle = (start+end)/2;

  /* sort the subarray from start..middle */
  merge_sort6(filename, table, start, middle);

  /* sort the subarray from middle..end */
  merge_sort6(filename, table, middle, end);

  /* merge the two sorted halves */
  merge6(filename, table, start, middle, end);
}

/*
   merge the subarray v[start..middle] with v[middle..end], placing the
   result back into v.
*/
void merge6(char *filename, struct networks6_table_entry *table, int start, int middle, int end)
{
  struct networks6_table_entry *v1, *v2;
  int v1_n, v2_n, v1_index, v2_index, i, x, s = sizeof(struct networks6_table_entry);
  int chunk;

  v1_n = middle-start;
  v2_n = end-middle;

  v1 = malloc(v1_n*s);
  v2 = malloc(v2_n*s);

  if ((!v1) || (!v2)) Log(LOG_ERR, "ERROR ( %s ): Memory sold out when allocating 'networks table'\n", filename);

  for (i=0; i<v1_n; i++) memcpy(&v1[i], &table[start+i], s);
  for (i=0; i<v2_n; i++) memcpy(&v2[i], &table[middle+i], s);

  v1_index = 0;
  v2_index = 0;

  /* as we pick elements from one or the other to place back into the table */
  for (i=0; (v1_index < v1_n) && (v2_index < v2_n); i++) {
    /* current v1 element less than current v2 element? */
    for (chunk = 0; chunk < 4; chunk++) { 
      if (v1[v1_index].net[chunk] < v2[v2_index].net[chunk]) {
        memcpy(&table[start+i], &v1[v1_index++], s);
	break;
      }
      if (v1[v1_index].net[chunk] > v2[v2_index].net[chunk]) {
        memcpy(&table[start+i], &v2[v2_index++], s);
	break;
      }
      if (v1[v1_index].net[chunk] == v2[v2_index].net[chunk]) {
        if (chunk != 3) continue;
        else {
	  /* two network prefixes are identical; let's compare their masks */
	  for (x = 0; x < 4; x++) {
            if (v1[v1_index].mask[x] < v2[v2_index].mask[x]) {
	      memcpy(&table[start+i], &v1[v1_index++], s);
	      break;
	    }
	    if (v1[v1_index].mask[x] > v2[v2_index].mask[x]) {
              memcpy(&table[start+i], &v2[v2_index++], s);
              break;
            }
	    if (v1[v1_index].mask[x] == v2[v2_index].mask[x]) {
	      if (x != 3) continue;
	      else memcpy(&table[start+i], &v1[v1_index++], s);
	    }
	  }
	}
      }
    }
  }

  /* clean up; either v1 or v2 may have stuff left in it */
  for (; v1_index < v1_n; i++) memcpy(&table[start+i], &v1[v1_index++], s);
  for (; v2_index < v2_n; i++) memcpy(&table[start+i], &v2[v2_index++], s);

  free(v1);
  free(v2);
}

struct networks6_table_entry *binsearch6(struct networks_table *nt, struct networks_cache *nc, struct host_addr *a)
{
  int low = 0, mid, high = nt->num6-1, chunk;
  u_int32_t net[4], addrh[4], addr[4]; 
  struct networks6_table_entry *ret;

  memcpy(&addr, &a->address.ipv6, IP6AddrSz);
  memcpy(&addrh, &a->address.ipv6, IP6AddrSz);
  memcpy(&addrh, (void *) pm_ntohl6(addrh), IP6AddrSz);
  
  ret = networks_cache_search6(nc, addr);
  if (ret) return ret;

  binsearch_loop:
  while (low <= high) {
    mid = (low+high)/2;
    memcpy(&net, &addrh, IP6AddrSz); 

    for (chunk = 0; chunk < 4; chunk++) net[chunk] &= nt->table6[mid].mask[chunk];
    for (chunk = 0; chunk < 4; chunk++) {
      if (net[chunk] < nt->table6[mid].net[chunk]) {
        high = mid-1;
        goto binsearch_loop;
      }
      else if (net[chunk] > nt->table6[mid].net[chunk]) {
        low = mid+1;
        goto binsearch_loop;
      }
    }
  
    /* It's assumed we've found our element */
    if (nt->table6[mid].childs_table.table6) {
      ret = binsearch6(&nt->table6[mid].childs_table, nc, a);
      if (!ret) {
        ret = &nt->table6[mid];
        networks_cache_insert6(nc, addr, &nt->table6[mid]);
      }
    }
    else {
      ret = &nt->table6[mid];
      networks_cache_insert6(nc, addr, &nt->table6[mid]);
    }
    return ret;
  }

  networks_cache_insert6(nc, addr, &dummy_entry6);
  return NULL;
}

void networks_cache_insert6(struct networks_cache *nc, void *key, struct networks6_table_entry *result)
{
  struct networks6_cache_entry *ptr;
  unsigned int hash;
  u_int32_t *keyptr = key;
  int chunk;

  hash = networks_cache_hash6(key); 
  ptr = &nc->cache6[hash % nc->num6];
  memcpy(ptr->key, keyptr, IP6AddrSz); 
  ptr->result = result;
}

struct networks6_table_entry *networks_cache_search6(struct networks_cache *nc, void *key)
{
  struct networks6_cache_entry *ptr;
  unsigned int hash;
  u_int32_t *keyptr = key;
  int chunk;

  hash = networks_cache_hash6(key);
  ptr = &nc->cache6[hash % nc->num6];
  for (chunk = 0; chunk < 4; chunk++) {
    if (ptr->key[chunk] == keyptr[chunk]) continue;
    else return NULL;
  } 

  return ptr->result;
}

unsigned int networks_cache_hash6(void *key)
{
  u_int32_t a, b, c;
  u_int32_t *keyptr = (u_int32_t *)key;

  a = keyptr[0];
  b = keyptr[1];
  c = keyptr[2];

  a += JHASH_GOLDEN_RATIO;
  b += JHASH_GOLDEN_RATIO;
  c += 140281; /* trivial hash rnd */
  __jhash_mix(a, b, c);

  return c;
}
#endif
