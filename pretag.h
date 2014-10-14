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

/* Pre-Tag map stuff */
#define N_MAP_HANDLERS 10 

typedef int (*pretag_handler) (struct packet_ptrs *, void *, void *);

struct id_entry {
  u_int16_t id;
  struct host_addr agent_ip;
  struct host_addr nexthop;
  struct host_addr bgp_nexthop;
  u_int16_t input; /* input interface index */
  u_int16_t output; /* output interface index */
  u_int8_t engine_type;
  u_int8_t engine_id;
  struct bpf_program filter;
  u_int8_t v8agg;
  pretag_handler func[N_MAP_HANDLERS];
};

struct id_table {
  unsigned short int num;
  struct id_entry *ipv4_base;
  unsigned short int ipv4_num;
#if defined ENABLE_IPV6
  struct id_entry *ipv6_base;
  unsigned short int ipv6_num;
#endif
  struct id_entry e[MAX_MAP_ENTRIES];
};

struct _map_dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(struct id_entry *, char *);
};

struct pretag_filter {
  u_int16_t num;
  u_int16_t table[MAX_MAP_ENTRIES/4];
};

/* prototypes */
#if (!defined __PRETAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_id_file(int, char *, struct id_table *);

#undef EXT
