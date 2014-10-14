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

#define __CFG_HANDLERS_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "cfg_handlers.h"

int parse_truefalse(char *value_ptr)
{
  int value;

  lower_string(value_ptr);
  
  if (!strcmp("true", value_ptr)) value = TRUE;
  else if (!strcmp("false", value_ptr)) value = FALSE;
  else value = ERR;

  return value;
}

int cfg_key_debug(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr); 
  if (value < 0) return ERR; 

  if (!name) for (; list; list = list->next, changes++) list->cfg.debug = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) { 
	list->cfg.debug = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_syslog(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.syslog = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.syslog = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pidfile(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pidfile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'pidfile'. Globalized.\n");

  return changes;
}

int cfg_key_daemonize(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.daemon = value;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'daemonize'. Globalized.\n"); 

  return changes;
}

int cfg_key_aggregate(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token;
  u_int32_t value = 0, changes = 0; /* XXX: 'value' to be changed in unsigned long int ? */

  trim_all_spaces(value_ptr);

  while (count_token = extract_token(&value_ptr, ',')) {
    if (!strcmp(count_token, "src_host")) value |= COUNT_SRC_HOST;
    else if (!strcmp(count_token, "dst_host")) value |= COUNT_DST_HOST;
    else if (!strcmp(count_token, "src_net")) value |= COUNT_SRC_NET;
    else if (!strcmp(count_token, "dst_net")) value |= COUNT_DST_NET;
    else if (!strcmp(count_token, "sum")) value |= COUNT_SUM_HOST;
    else if (!strcmp(count_token, "src_port")) value |= COUNT_SRC_PORT;
    else if (!strcmp(count_token, "dst_port")) value |= COUNT_DST_PORT;
    else if (!strcmp(count_token, "proto")) value |= COUNT_IP_PROTO;
    else if (!strcmp(count_token, "src_mac")) value |= COUNT_SRC_MAC;
    else if (!strcmp(count_token, "dst_mac")) value |= COUNT_DST_MAC;
    else if (!strcmp(count_token, "vlan")) value |= COUNT_VLAN;
    else if (!strcmp(count_token, "tos")) value |= COUNT_IP_TOS;
    else if (!strcmp(count_token, "none")) value |= COUNT_NONE;
    else if (!strcmp(count_token, "src_as")) value |= COUNT_SRC_AS;
    else if (!strcmp(count_token, "dst_as")) value |= COUNT_DST_AS;
    else if (!strcmp(count_token, "sum_host")) value |= COUNT_SUM_HOST;
    else if (!strcmp(count_token, "sum_net")) value |= COUNT_SUM_NET;
    else if (!strcmp(count_token, "sum_as")) value |= COUNT_SUM_AS;
    else if (!strcmp(count_token, "sum_port")) value |= COUNT_SUM_PORT;
    else if (!strcmp(count_token, "tag")) value |= COUNT_ID;
    else Log(LOG_WARNING, "WARN: ignoring unknown aggregation method: %s.\n", count_token);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.what_to_count = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.what_to_count = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_aggregate_filter(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: aggregation filter cannot be global. Not loaded.\n");
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.a_filter = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag_filter(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token;
  int value, changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: ID filter cannot be global. Not loaded.\n");
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	trim_all_spaces(value_ptr);

	list->cfg.ptf.num = 0;
	while ((count_token = extract_token(&value_ptr, ',')) && changes < MAX_MAP_ENTRIES/4) {
	  value = atoi(count_token);
	  if ((value < 0) || (value > 65535)) {
	    Log(LOG_ERR, "WARN: 'pre_tag_filter' values has to be in the range 0-65535. '%d' not loaded.\n", value);
	    changes++;
	  }
	  else {
            list->cfg.ptf.table[list->cfg.ptf.num] = value;
	    list->cfg.ptf.num++;
            changes++;
	  }
	}
        break;
      }
    }
  }

  return changes;
}


int cfg_key_pcap_filter(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.clbuf = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'pcap_filter'. Globalized.\n");

  return changes;
}

int cfg_key_interface(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.dev = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'interface'. Globalized.\n");

  return changes;
}

int cfg_key_interface_wait(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.if_wait = value;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'interface_wait'. Globalized.\n");

  return changes;
}

int cfg_key_promisc(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.promisc = value;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'promisc'. Globalized.\n");

  return changes;
}

int cfg_key_imt_path(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_path = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_path = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_passwd(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_buckets(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "ERROR: invalid number of buckets.\n");
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.buckets = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buckets = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_mem_pools_number(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;
  
  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "ERROR: invalid number of memory pools.\n");
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_memory_pools = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_memory_pools = value;
        changes++;
        break;
      }
    }
  }

  have_num_memory_pools = TRUE;
  return changes;
}

int cfg_key_imt_mem_pools_size(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.memory_pool_size = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.memory_pool_size = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_db(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_db = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_db = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_version(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "ERROR: invalid 'sql_table_version' value.\n");
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_version = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_version = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_data(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_data = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_data = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_host(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_recovery_backup_host(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_backup_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_backup_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_exec(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_trigger_exec = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_exec = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_time(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, t, t_howmany;

  parse_time(value_ptr, &t, &t_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_trigger_time = t;
      list->cfg.sql_trigger_time_howmany = t_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_time = t;
	list->cfg.sql_trigger_time_howmany = t_howmany;
	changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_user(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_user = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_user = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_passwd(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_refresh_time(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: 'sql_refresh_time' has to be > 0\n");
    return ERR;
  }
     
  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_startup_delay(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_startup_delay = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_startup_delay = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_optimize_clauses(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_optimize_clauses = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_optimize_clauses = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history_roundoff(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  int i, check, len;

  len = strlen(value_ptr);
  for (i = 0, check = 0; i < len; i++) {
    if (value_ptr[i] == 'd') check |= COUNT_DAILY;
    if (value_ptr[i] == 'w') check |= COUNT_WEEKLY;
    if (value_ptr[i] == 'M') check |= COUNT_MONTHLY;
  } 
  if (((check & COUNT_DAILY) || (check & COUNT_MONTHLY)) && (check & COUNT_WEEKLY)) {
    Log(LOG_ERR, "WARN: 'sql_history_roundoff' 'w' is not compatible with either 'd' or 'M'.\n");
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_history_roundoff = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history_roundoff = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_recovery_logfile(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_recovery_logfile = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_recovery_logfile = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, sql_history, sql_history_howmany;

  parse_time(value_ptr, &sql_history, &sql_history_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_history = sql_history;
      list->cfg.sql_history_howmany = sql_history_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history = sql_history;
        list->cfg.sql_history_howmany = sql_history_howmany;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_cache_entries(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_cache_entries = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_cache_entries = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_dont_try_update(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_dont_try_update = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_dont_try_update = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_preprocess(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_preprocess = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_preprocess = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_size(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_size = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_size = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_buffer_size(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.buffer_size = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buffer_size = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_cache_entries(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_cache_entries = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_cache_entries = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_ports_file(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.ports_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.ports_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_refresh_time(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: 'print_refresh_time' has to be > 0\n");
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_cache_entries(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_cache_entries = atoi(value_ptr);
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_cache_entries = atoi(value_ptr);
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_markers(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_markers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_markers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_post_tag(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 1) || (value > 65535)) {
    Log(LOG_ERR, "WARN: 'post_tag' has to be in the range 1-65535.\n");
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.post_tag = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.post_tag = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sampling_rate(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN: 'sampling_rate' has to be >= 1.\n");
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sampling_rate = value-1;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sampling_rate = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfacctd_port(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: 'nfacctd_port' has to be in the range 0-65535.\n");
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_port = value;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_port'. Globalized.\n");

  return changes;
}

int cfg_key_nfacctd_ip(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_ip'. Globalized.\n");

  return changes;
}

int cfg_key_nfacctd_allow_file(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_allow_file'. Globalized.\n");

  return changes;
}

int cfg_key_pre_tag_map(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pre_tag_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'pre_tag_map'. Globalized.\n");

  return changes;
}

int cfg_key_nfacctd_time_secs(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_time = NF_TIME_SECS;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_time_secs'. Globalized.\n");

  return changes;
}

int cfg_key_nfacctd_time_new(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_time = NF_TIME_NEW;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_time_new'. Globalized.\n");

  return changes;
}

int cfg_key_pmacctd_force_frag_handling(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.handle_fragments = TRUE;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'pmacctd_force_frag_handling'. Globalized.\n");

  return changes;
}

int cfg_key_pcap_savefile(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pcap_savefile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'pcap_savefile'. Globalized.\n");

  return changes;
}

int cfg_key_nfacctd_as_new(char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_as = NF_AS_NEW;
  if (name) Log(LOG_WARNING, "WARN: plugin name not supported for key 'nfacctd_as_new'. Globalized.\n");

  return changes;
}

void parse_time(char *value, int *mu, int *howmany)
{
  int k, j, len;

  len = strlen(value);
  for (j = 0; j < len; j++) {
    if (!isdigit(value[j])) {
      if (value[j] == 'm') *mu = COUNT_MINUTELY;
      else if (value[j] == 'h') *mu = COUNT_HOURLY;
      else if (value[j] == 'd') *mu = COUNT_DAILY;
      else if (value[j] == 'w') *mu = COUNT_WEEKLY;
      else if (value[j] == 'M') *mu = COUNT_MONTHLY;
      else {
        Log(LOG_WARNING, "WARN: Ignoring unknown time measuring unit: '%c'.\n", value[j]);
        *mu = 0;
        *howmany = 0;
        return;
      }
      if (*mu) {
        value[j] = '\0';
        break;
      }
    }
  }
  k = atoi(value);
  if (k > 0) *howmany = k;
  else {
    Log(LOG_WARNING, "WARN: ignoring invalid time value: %d\n", k);
    *mu = 0;
    *howmany = 0;
  }
}

