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

/* structures */
struct cidr_table_entry {
  char value[20];
};

struct networks_table {
  struct networks_table_entry *table;
  int num;
};

struct networks_table_entry {
  u_int32_t net;
  u_int32_t mask; 
  struct networks_table childs_table;
  // int childs_num;
};

struct networks_table_metadata {
  u_int8_t level;
  u_int32_t childs;
};

static struct cidr_table_entry cidr_table[] = {
  "0.0.0.0",
  "128.0.0.0",
  "192.0.0.0",
  "224.0.0.0",
  "240.0.0.0",
  "248.0.0.0",
  "252.0.0.0",
  "254.0.0.0",
  "255.0.0.0",
  "255.128.0.0",
  "255.192.0.0",
  "255.224.0.0",
  "255.240.0.0",
  "255.248.0.0",
  "255.252.0.0",
  "255.254.0.0",
  "255.255.0.0",
  "255.255.128.0",
  "255.255.192.0",
  "255.255.224.0",
  "255.255.240.0",
  "255.255.248.0",
  "255.255.252.0",
  "255.255.254.0",
  "255.255.255.0",
  "255.255.255.128",
  "255.255.255.192",
  "255.255.255.224",
  "255.255.255.240",
  "255.255.255.248",
  "255.255.255.252",
  "255.255.255.254",
  "255.255.255.255",
};

/* prototypes */
#if (!defined __NET_AGGR_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_networks(char *, struct networks_table *); 
EXT void merge_sort(struct networks_table_entry *, int, int);
EXT void merge(struct networks_table_entry *, int, int, int);
EXT int binsearch(struct networks_table *, struct in_addr *);
#undef EXT

