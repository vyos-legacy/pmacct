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

/* prototypes */
#if (!defined __CFG_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif

EXT int set_all_int(unsigned int, int);
EXT int set_one_int(unsigned int, char *, int);
EXT int set_all_char_ptr(unsigned int, char *);
EXT int set_one_char_ptr(unsigned int, char *, char *);
EXT int parse_truefalse(char *);
EXT int cfg_key_debug(char *, char *);
EXT int cfg_key_syslog(char *, char *);
EXT int cfg_key_pidfile(char *, char *);
EXT int cfg_key_daemonize(char *, char *);
EXT int cfg_key_aggregate(char *, char *);
EXT int cfg_key_aggregate_filter(char *, char *);
EXT int cfg_key_pcap_filter(char *, char *);
EXT int cfg_key_interface(char *, char *);
EXT int cfg_key_interface_wait(char *, char *);
EXT int cfg_key_promisc(char *, char *);
EXT int cfg_key_imt_path(char *, char *);
EXT int cfg_key_imt_passwd(char *, char *);
EXT int cfg_key_imt_buckets(char *, char *);
EXT int cfg_key_imt_mem_pools_number(char *, char *);
EXT int cfg_key_imt_mem_pools_size(char *, char *);
EXT int cfg_key_sql_db(char *, char *);
EXT int cfg_key_sql_table(char *, char *);
EXT int cfg_key_sql_table_version(char *, char *);
EXT int cfg_key_sql_host(char *, char *);
EXT int cfg_key_sql_data(char *, char *);
EXT int cfg_key_sql_user(char *, char *);
EXT int cfg_key_sql_passwd(char *, char *);
EXT int cfg_key_sql_refresh_time(char *, char *);
EXT int cfg_key_sql_startup_delay(char *, char *);
EXT int cfg_key_sql_optimize_clauses(char *, char *);
EXT int cfg_key_sql_history(char *, char *);
EXT int cfg_key_sql_history_roundoff(char *, char *);
EXT int cfg_key_sql_recovery_logfile(char *, char *);
EXT int cfg_key_sql_recovery_backup_host(char *, char *);
EXT int cfg_key_sql_trigger_exec(char *, char *);
EXT int cfg_key_sql_trigger_time(char *, char *);
EXT int cfg_key_sql_cache_entries(char *, char *);
EXT int cfg_key_sql_dont_try_update(char *, char *);
EXT int cfg_key_sql_preprocess(char *, char *);
EXT int cfg_key_plugin_pipe_size(char *, char *);
EXT int cfg_key_plugin_buffer_size(char *, char *);
EXT int cfg_key_networks_file(char *, char *);
EXT int cfg_key_networks_cache_entries(char *, char *);
EXT int cfg_key_ports_file(char *, char *);
EXT int cfg_key_print_refresh_time(char *, char *);
EXT int cfg_key_print_cache_entries(char *, char *);
EXT int cfg_key_print_markers(char *, char *);
EXT int cfg_key_nfacctd_port(char *, char *);
EXT int cfg_key_nfacctd_ip(char *, char *);
EXT int cfg_key_nfacctd_allow_file(char *, char *);
EXT int cfg_key_nfacctd_time_secs(char *, char *);
EXT int cfg_key_nfacctd_time_new(char *, char *);
EXT int cfg_key_nfacctd_as_new(char *, char *);
EXT int cfg_key_pmacctd_force_frag_handling(char *, char *);
EXT int cfg_key_pcap_savefile(char *, char *);
EXT int cfg_key_pre_tag_map(char *, char *);
EXT int cfg_key_pre_tag_filter(char *, char *);
EXT int cfg_key_post_tag(char *, char *);
EXT int cfg_key_sampling_rate(char *, char *);

EXT void parse_time(char *, int *, int *);
#undef EXT
