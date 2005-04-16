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

/* includes */
#include <sys/poll.h>

/* defines */
#define DEFAULT_DB_REFRESH_TIME 60
#define DEFAULT_SQL_TABLE_VERSION 1
#define CACHE_ENTRIES 32771 
#define QUERY_BUFFER_SIZE 32768
#define MAGIC 14021979
#define DEF_HDR_FIELD_LEN 128 
#define UINT32TMAX 4290000000 
#define MAX_LOGFILE_SIZE 2048000000 
#define MAX_LOGFILE_ROTATIONS 1000

/* cache elements defines */
#define REASONABLE_NUMBER 100
#define STALE_M 3
#define RETIRE_M STALE_M*STALE_M

/* macros */
#define SPACELEFT(x) (sizeof(x)-strlen(x))

/* structures */
struct insert_data {
  unsigned int hash;
  unsigned int modulo;
  time_t now;
  time_t basetime;   
  time_t triggertime;
  time_t timeslot;   /* counters timeslot */ 
  time_t t_timeslot; /* trigger timeslot */
  int num_primitives;
  /* stats */
  time_t elap_time; /* elapsed time */
  unsigned int ten; /* total elements number */
  unsigned int een; /* effective elements number */ 
  unsigned int iqn; /* INSERTs query number */
  unsigned int uqn; /* UPDATEs query number */
};

struct db_cache {
  u_int8_t eth_dhost[ETH_ADDR_LEN];
  u_int8_t eth_shost[ETH_ADDR_LEN];
  u_int16_t vlan_id;
  struct host_addr src_ip;
  struct host_addr dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t tos;
  u_int8_t proto;
  u_int16_t id;
  u_int32_t bytes_counter;
  u_int32_t packet_counter;
  time_t basetime;
  int valid;
  unsigned int signature;
  u_int8_t chained;
  struct db_cache *prev;
  struct db_cache *next;
  time_t lru_tag;
  struct db_cache *lru_prev;
  struct db_cache *lru_next;
};

struct logfile_header {
  u_int32_t magic;
  char sql_db[DEF_HDR_FIELD_LEN];
  char sql_table[DEF_HDR_FIELD_LEN];
  char sql_user[DEF_HDR_FIELD_LEN];
  char sql_host[DEF_HDR_FIELD_LEN];
  u_int16_t sql_table_version;
  u_int16_t sql_optimize_clauses;
  u_int16_t sql_history;
  u_int32_t what_to_count;
  u_char pad[8];
};

struct logfile {
  FILE *file;
  short int open;
  short int fail;
};

typedef void (*dbop_handler) (const struct db_cache *, int, char **, char **);
typedef int (*preprocess_func) (struct db_cache *[], int *);

struct frags {
  dbop_handler handler;
  unsigned long int type;
  char string[SRVBUFLEN];
};

/* functions */
#if (!defined __SQL_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void count_src_mac_handler(const struct db_cache *, int, char **, char **);
EXT void count_dst_mac_handler(const struct db_cache *, int, char **, char **);
EXT void count_vlan_handler(const struct db_cache *, int, char **, char **);
EXT void count_src_host_handler(const struct db_cache *, int, char **, char **);
EXT void count_src_as_handler(const struct db_cache *, int, char **, char **);
EXT void count_dst_host_handler(const struct db_cache *, int, char **, char **);
EXT void count_dst_as_handler(const struct db_cache *, int, char **, char **);
EXT void count_src_port_handler(const struct db_cache *, int, char **, char **);
EXT void count_dst_port_handler(const struct db_cache *, int, char **, char **);
EXT void count_ip_tos_handler(const struct db_cache *, int, char **, char **);
EXT void MY_count_ip_proto_handler(const struct db_cache *, int, char **, char **);
EXT void PG_count_ip_proto_handler(const struct db_cache *, int, char **, char **);
EXT void count_timestamp_handler(const struct db_cache *, int, char **, char **);
EXT void count_id_handler(const struct db_cache *, int, char **, char **);
EXT void fake_mac_handler(const struct db_cache *, int, char **, char **);
EXT void fake_host_handler(const struct db_cache *, int, char **, char **);
#undef EXT

/* global vars: a simple way of gain precious speed when playing with strings */
#if (!defined __MYSQL_PLUGIN_C) && (!defined __PMACCT_PLAYER_C) && \
	(!defined __PGSQL_PLUGIN_C) 
#define EXT extern
#else
#define EXT
#endif

EXT char sql_data[LONGLONGSRVBUFLEN];
EXT char lock_clause[LONGSRVBUFLEN];
EXT char unlock_clause[LONGSRVBUFLEN];
EXT char update_clause[LONGSRVBUFLEN];
EXT char insert_clause[LONGSRVBUFLEN];
EXT char values_clause[LONGSRVBUFLEN];
EXT char where_clause[LONGSRVBUFLEN];
EXT struct db_cache *cache;
EXT struct db_cache **queries_queue;
EXT struct db_cache *collision_queue;
EXT int cq_ptr, qq_ptr, qq_size, pp_size, dbc_size, cq_size;
EXT struct db_cache lru_head, *lru_tail;
EXT struct frags where[N_PRIMITIVES+2];
EXT struct frags values[N_PRIMITIVES+2];
EXT int num_primitives; /* last resort for signal handling */
#undef EXT

/* the following include depends on structure definition above */
#include "log_templates.h"
#include "preprocess.h"
