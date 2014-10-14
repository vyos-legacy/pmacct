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

#define __NET_AGGR_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "net_aggr.h"
#include "util.h"

void load_networks(char *filename, struct networks_table *nt)
{
  FILE *file;
  struct networks_table tmp, *tmpt = &tmp; 
  struct networks_table_metadata *mdt;
  char buf[SRVBUFLEN], *delim, *net, *mask;
  int rows, index, eff_rows = 0;

  if (filename) {
    if ((file = fopen(filename,"r")) == NULL) {
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
	memset(buf, 0, SRVBUFLEN);
        if (fgets(buf, SRVBUFLEN, file)) { 
	  if (!sanitize_buf_net(buf, rows)) {
	    delim = strchr(buf, '/');
	    *delim = '\0';
	    net = buf;
	    mask = delim+1;
	    if (!strchr(mask, '.')) {
	      index = atoi(mask); 
	      if ((index >= 0) && (index <= 32)) mask = cidr_table[index].value; 
	      else Log(LOG_ERR, "ERROR: invalid network mask '/%d'\n", index);
	    }
	    inet_aton(net, (struct in_addr *) &tmpt->table[eff_rows].net);
	    inet_aton(mask, (struct in_addr *) &tmpt->table[eff_rows].mask);

	    tmpt->table[eff_rows].net = ntohl(tmpt->table[eff_rows].net);
	    tmpt->table[eff_rows].mask = ntohl(tmpt->table[eff_rows].mask);

	    /* we will insert in the networks table only valid values; 0.0.0.0/0
	       is not and we silently discard it */ 
	    if ((!tmpt->table[eff_rows].net) && (!tmpt->table[eff_rows].mask));
	    else eff_rows++;
	  } 
	}
	rows++;
      }
      fclose(file);

      /* 3rd step: sorting table */
      merge_sort(tmpt->table, 0, eff_rows);
      tmpt->num = eff_rows;

      /* 4th step: collecting informations in the sorted table;
         we wish to handle networks-in-networks hierarchically */

      /* 4a building hierarchies */
      mdt = malloc(tmpt->num*sizeof(struct networks_table_metadata));
      memset(mdt, 0, tmpt->num*sizeof(struct networks_table_metadata));

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
	  Log(LOG_DEBUG, "DEBUG: (networks table) net: %x, mask: %x\n", nt->table[index].net, nt->table[index].mask); 
	  // Log(LOG_DEBUG, "DEBUG: (networks table) net: %x, mask: %x, level: %u, childs: %u\n",
	  //   tmpt->table[index].net, tmpt->table[index].mask, mdt[index].level, mdt[index].childs); 
	  index++;
	}
      }
    }
  }
}

/* sort the (sub)array v from start to end */
void merge_sort(struct networks_table_entry *table, int start, int end)
{
  int middle;

  /* no elements to sort */
  if ((start == end) || (start == end-1)) return;

  /* find the middle of the array, splitting it into two subarrays */
  middle = (start+end)/2;

  /* sort the subarray from start..middle */
  merge_sort(table, start, middle);

  /* sort the subarray from middle..end */
  merge_sort(table, middle, end);

  /* merge the two sorted halves */
  merge(table, start, middle, end);
}

/* 
   merge the subarray v[start..middle] with v[middle..end], placing the
   result back into v.
*/
void merge(struct networks_table_entry *table, int start, int middle, int end)
{
  struct networks_table_entry *v1, *v2;
  int  v1_n, v2_n, v1_index, v2_index, i, s = sizeof(struct networks_table_entry);

  v1_n = middle-start;
  v2_n = end-middle;

  v1 = malloc(v1_n*s);
  v2 = malloc(v2_n*s);

  if ((!v1) || (!v2)) Log(LOG_ERR, "ERROR: Memory sold out when allocating 'networks table'\n"); 

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

int binsearch(struct networks_table *nt, struct in_addr *a)
{
  int low = 0, mid, high = nt->num-1;
  u_int32_t net, addr = a->s_addr;

  while (low <= high) {
    mid = (low+high)/2;
    net = ntohl(a->s_addr);
    net &= nt->table[mid].mask;
    if (net == nt->table[mid].net) {
      if (nt->table[mid].childs_table.table) {
	if (!binsearch(&nt->table[mid].childs_table, a)) a->s_addr = htonl(net);
      }
      else a->s_addr = htonl(net);
      return TRUE;
    }
    else if (net < nt->table[mid].net) high = mid-1;
    else low = mid+1; 
  }

  a->s_addr = 0;
  return FALSE;
}

