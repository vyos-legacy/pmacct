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

#include "cfg_handlers.h"

/* defines */
#define CFG_LINE_LEN(x) (SRVBUFLEN-strlen(x))

/* structures */
struct _dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(char *, char *, char *);
};

struct configuration {
  char *name;
  char *type;
  u_int32_t what_to_count;
  int acct_type; 
  int pipe_size;
  int buffer_size;
  int handle_fragments;
  int handle_flows;
  int frag_bufsz;
  int flow_bufsz;
  int flow_lifetime;
  char *imt_plugin_path;
  char *imt_plugin_passwd;
  char *sql_db;
  char *sql_table;
  char *sql_table_schema;
  int sql_table_version;
  char *sql_user;
  char *sql_passwd;
  char *sql_host;
  char *sql_data;
  char *sql_backup_host;
  int sql_optimize_clauses;
  int sql_refresh_time;
  int sql_history;
  int sql_history_howmany; /* internal */
  int sql_startup_delay;
  int sql_cache_entries;
  int sql_dont_try_update;
  char *sql_history_roundoff;
  char *sql_recovery_logfile;
  int sql_trigger_time;
  int sql_trigger_time_howmany; /* internal */
  char *sql_trigger_exec;
  int sql_max_queries;
  char *sql_preprocess;
  int sql_preprocess_type;
  int sql_multi_values;
  int print_refresh_time;
  int print_cache_entries;
  int print_markers;
  int nfacctd_port;
  char *nfacctd_ip;
  char *nfacctd_allow_file;
  int nfacctd_time;
  int nfacctd_as;
  int promisc; /* pcap_open_live() promisc parameter */
  char *clbuf; /* pcap filter */
  char *pcap_savefile;
  char *dev;
  int if_wait;
  int num_memory_pools;
  int memory_pool_size;
  int buckets;
  int daemon;
  int active_plugins;
  char *pidfile; 
  int networks_mask;
  char *networks_file;
  int networks_cache_entries;
  char *ports_file;
  char *a_filter;
  struct bpf_program bpfp_a_filter;
  struct pretag_filter ptf;
  char *pre_tag_map;
  int post_tag;
  int sampling_rate;
  char *syslog;
  int debug;
  int snaplen;
};

struct plugin_type_entry {
  char string[10];
  void (*func)(int, struct configuration *, void *);
};

struct plugins_list_entry {
  int id;
  pid_t pid;
  char name[SRVBUFLEN];
  struct configuration cfg;
  int pipe[2];
  struct plugin_type_entry type;
  struct plugins_list_entry *next;
};

/* prototypes */ 
#if (!defined __CFG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void evaluate_configuration(char *, int);
EXT int parse_configuration_file(char *);
EXT int parse_plugin_names(char *, int, int);
EXT void debug_configuration_file(char *, int);
EXT int create_plugin(char *, char *, char *);
EXT int delete_plugin_by_id(int);
EXT struct plugins_list_entry *search_plugin_by_pipe(int);
EXT struct plugins_list_entry *search_plugin_by_pid(pid_t);
EXT void sanitize_cfg(int, char *);
EXT void set_default_values();

/* global vars */
EXT char *cfg[SRVBUFLEN];
EXT int rows;
#undef EXT
