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

/* defines */
#define NUM_MEMORY_POOLS 16
#define MEMORY_POOL_SIZE 8192
#define MAX_HOSTS 255

/* Structures */
struct acc {
  u_int8_t eth_dhost[ETH_ADDR_LEN];
  u_int8_t eth_shost[ETH_ADDR_LEN];
  u_int16_t vlan_id;
  struct in_addr src_ip;
  struct in_addr dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port; 
  u_int8_t proto;
  u_int16_t id;
  int packet_counter;
  int bytes_counter;
#if defined (HAVE_MMAP)
  u_int8_t reset_flag;
#endif
  struct acc *next;
};

struct bucket_desc {
  unsigned int num;
  unsigned short int howmany;
};

struct memory_pool_desc {
  int id;
  unsigned char *base_ptr;
  unsigned char *ptr;
  int space_left;
  int len;
  struct memory_pool_desc *next;
};

struct query_header {
  int type;
  unsigned int what_to_count;
  char passwd[8];
};

/* prototypes */
char *extract_token(char **, int);
struct acc *insert_accounting_structure(struct pkt_data *);
struct acc *search_accounting_structure(struct pkt_primitives *);
void set_reset_flag(struct acc *);
void reset_counters(struct acc *);
void init_memory_pool_table();
void clear_memory_pool_table();
struct memory_pool_desc *request_memory_pool(int);
int build_query_server(char *);
void process_query_data(int, unsigned char *, int);
void mask_elem(struct pkt_primitives *, struct acc *, unsigned int);
void exit_now(int);

/* global vars */
unsigned char *mpd;  /* memory pool descriptors table */
unsigned char *a;  /* accounting in-memory table */
struct memory_pool_desc *current_pool; /* pointer to currently used memory pool */
struct acc **lru_elem_ptr; /* pointer to Last Recently Used (lru) element in a bucket */
int no_more_space;
