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

#define __MYSQL_PLUGIN_C

#define REASONABLE_NUMBER 1000

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "mysql_plugin.h"
#include "net_aggr.h"
#include "util.h"
#include "crc32.c"

/* Functions */
void mysql_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct networks_table nt;
  unsigned char *pipebuf;
  char mysql_user[] = "pmacct";
  char mysql_pwd[] = "arealsmartpwd";
  char mysql_db[] = "pmacct"; 
  char mysql_table[] = "acct";
  char mysql_table_v2[] = "acct_v2";
  struct pollfd pfd;
  struct insert_data idata;
  time_t t, now, refresh_deadline;
  int timeout;
  int ret;
#if defined (HAVE_MMAP)
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0; 
#endif

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));

  /* signal handling */
  signal(SIGINT, MY_exit_gracefully);
  signal(SIGHUP, reload); /* handles reopening of syslog channel */

  /* checks */
  if (config.what_to_count & COUNT_SUM_HOST) {
    Log(LOG_ERR, "ERROR: Option available only in memory table operations\nExiting ...\n\n");
    exit(1);
  }

  if (!config.sql_refresh_time)
    config.sql_refresh_time = DEFAULT_DB_REFRESH_TIME;

  if (!config.sql_table_version)
    config.sql_table_version = DEFAULT_SQL_TABLE_VERSION;

  timeout = config.sql_refresh_time*1000; /* dirty */

  if (config.networks_file) load_networks(config.networks_file, &nt);
  
  memset(sql_data, 0, sizeof(sql_data));
  memset(lock_clause, 0, sizeof(lock_clause));
  memset(unlock_clause, 0, sizeof(unlock_clause));
  memset(update_clause, 0, sizeof(update_clause));
  memset(insert_clause, 0, sizeof(insert_clause));
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));

  qq_ptr = 0;
  cq_ptr = 0;
  cq_size = config.sql_refresh_time*REASONABLE_NUMBER;
  pp_size = sizeof(struct pkt_primitives);
  dbc_size = sizeof(struct db_cache);

  collision_queue = (struct db_cache *) malloc(cq_size*sizeof(struct db_cache)); /* XXX: rough */
  pipebuf = (unsigned char *) malloc(config.buffer_size);
  if (!config.sql_cache_entries) config.sql_cache_entries = CACHE_ENTRIES; 
  cache = (struct db_cache *) malloc(config.sql_cache_entries*sizeof(struct db_cache)); 
  queries_queue = (struct db_cache **) malloc(config.sql_cache_entries*sizeof(struct db_cache *));

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  /* searching for user supplied values */ 
  if (!config.sql_user) config.sql_user = mysql_user; 
  if (!config.sql_db) config.sql_db = mysql_db;
  if (!config.sql_passwd) config.sql_passwd = mysql_pwd; 
  if (!config.sql_table) {
    if (config.sql_table_version == 2) config.sql_table = mysql_table_v2;
    else config.sql_table = mysql_table;
  }

  now = time(NULL);

  /* historical recording time init: basetime */
  if (config.sql_history) {
    idata.basetime = now; 
    if (config.sql_history == COUNT_MINUTELY)
      idata.timeslot = config.sql_history_howmany*60;
    else if (config.sql_history == COUNT_HOURLY)
      idata.timeslot = config.sql_history_howmany*3600;
    else if (config.sql_history == COUNT_DAILY)
      idata.timeslot = config.sql_history_howmany*86400; 

    /* round off stuff */
    t = roundoff_time(idata.basetime);
    while ((t+idata.timeslot) < idata.basetime) t += idata.timeslot; 
    idata.basetime = t;
  }

  /* sql triggers time init: deadline; if a trigger exec is specified but no
     time is supplied, use 'sql_refresh_time' as interval; this will result in
     a trigger being executed each time data is purged into the DB */
  if (config.sql_trigger_exec) {
    time_t deadline;

    deadline = now;
    if (config.sql_trigger_time == COUNT_MINUTELY)
      config.sql_trigger_time_howmany = config.sql_trigger_time_howmany*60;
    else if (config.sql_trigger_time == COUNT_HOURLY)
      config.sql_trigger_time_howmany = config.sql_trigger_time_howmany*3600;
    else if (config.sql_trigger_time == COUNT_DAILY)
      config.sql_trigger_time_howmany = config.sql_trigger_time_howmany*86400;
    else config.sql_trigger_time_howmany = config.sql_refresh_time; 

    /* round off stuff */
    t = roundoff_time(deadline);
    while ((t+config.sql_trigger_time_howmany) < deadline) t += config.sql_trigger_time_howmany;
    config.sql_trigger_time = t;
    config.sql_trigger_time += config.sql_trigger_time_howmany; /* it's a deadline not a basetime */
  }

  /* sql_refresh time init: deadline */
  refresh_deadline = now; 
  t = roundoff_time(refresh_deadline);
  while ((t+config.sql_refresh_time) < refresh_deadline) t += config.sql_refresh_time;
  refresh_deadline = t;
  refresh_deadline += (config.sql_refresh_time+config.sql_startup_delay); /* it's a deadline not a basetime */

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* composing the proper (filled with primitives used during
     the current execution) SQL strings */
  idata.num_primitives = MY_compose_static_queries();
  num_primitives = idata.num_primitives; 

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.sql_cache_entries*sizeof(struct db_cache));
  memset(queries_queue, 0, config.sql_cache_entries*sizeof(struct db_cache *));
  memset(collision_queue, 0, cq_size*sizeof(struct db_cache *));

  /* plugin main loop */
  for(;;) {
    poll_again:
#if defined (HAVE_MMAP)
    status->wakeup = TRUE;
#endif
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      if (qq_ptr) {
        switch (fork()) {
        case 0: /* Child */
	  /* we have to ignore signals to avoid loops:
	     because we are already forked */
	  signal(SIGINT, SIG_IGN);
	  signal(SIGHUP, SIG_IGN);

	  memset(&p, 0, sizeof(p));
	  memset(&b, 0, sizeof(b));

          if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
          MY_cache_purge(queries_queue, qq_ptr, idata.num_primitives, TRUE);
          if (cq_ptr) {
	    config.sql_dont_try_update = FALSE;
	    MY_cache_purge(&collision_queue, cq_ptr, idata.num_primitives, FALSE);
	  }
          
	  if (!p.fail) mysql_close(&p.desc);
  	  else if (b.connected) mysql_close(&b.desc);
          exit(0);
        default: /* Parent */
	  if (cq_ptr) cq_ptr = MY_cache_flush(&collision_queue, cq_ptr, FALSE);
          qq_ptr = MY_cache_flush(queries_queue, qq_ptr, TRUE);
	  refresh_deadline += config.sql_refresh_time; 
          break;
        }
      }
      break;
    default: /* we received data */
#if !defined (HAVE_MMAP)
      if ((ret = read(pipe_fd, pipebuf, config.buffer_size)) == 0) 
        exit(1); /* we exit silently; something happened at the write end */

      if (ret < 0) goto poll_again;
#else
      read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
	if (seq == 0) rg_err_count = FALSE;
	now = time(NULL); 
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0) 
	  exit(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
	if (!pollagain) {
	  pollagain = TRUE;
	  goto poll_again;
        }
	else {
	  rg_err_count++;
	  if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
            Log(LOG_ERR, "ERROR: We are missing data.\n");
            Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
            Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%d'.\n", config.pipe_size);
            Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%d'.\n", config.buffer_size);
            Log(LOG_ERR, "- increase system maximum socket size.\n\n");
	  }
          seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
	}
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;
#endif

      /* lazy sql refresh handling */ 
      if (now > refresh_deadline) {
        if (qq_ptr) {
          switch (fork()) {
          case 0: /* Child */
            /* we have to ignore signals to avoid loops:
               because we are already forked */
            signal(SIGINT, SIG_IGN);
            signal(SIGHUP, SIG_IGN);

            memset(&p, 0, sizeof(p));
            memset(&b, 0, sizeof(b));

            if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
            MY_cache_purge(queries_queue, qq_ptr, idata.num_primitives, TRUE);
            if (cq_ptr) {
	      config.sql_dont_try_update = FALSE;
	      MY_cache_purge(&collision_queue, cq_ptr, idata.num_primitives, FALSE);
	    }

	    if (config.sql_trigger_exec) {
	      if (now > config.sql_trigger_time) MY_Exec(config.sql_trigger_exec);
	    }

            if (!p.fail) mysql_close(&p.desc);
            else if (b.connected) mysql_close(&b.desc);
            exit(0);
          default: /* Parent */
	    if (cq_ptr) cq_ptr = MY_cache_flush(&collision_queue, cq_ptr, FALSE);
            qq_ptr = MY_cache_flush(queries_queue, qq_ptr, TRUE);
	    refresh_deadline += config.sql_refresh_time; 
            if (now > config.sql_trigger_time) config.sql_trigger_time  += config.sql_trigger_time_howmany;
            break;
	  }
        }
      } 
      else {
	if (config.sql_trigger_exec) {
	  if (now > config.sql_trigger_time) {
	    MY_Exec(config.sql_trigger_exec); 
	    config.sql_trigger_time  += config.sql_trigger_time_howmany;
	  }
	}
      }

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));
      if (now > (idata.basetime + idata.timeslot)) idata.basetime += idata.timeslot;

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	if (config.what_to_count & COUNT_SRC_NET)
	  binsearch(&nt, &data->primitives.src_ip);
	
	if (config.what_to_count & COUNT_DST_NET)
	  binsearch(&nt, &data->primitives.dst_ip);

        idata.modulo = MY_cache_modulo(&data->primitives); 
        MY_cache_insert(data, &idata); 
	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) data++;
      }
#if defined (HAVE_MMAP)
      goto read_data;
#endif
    }
  }
}

unsigned int MY_cache_modulo(struct pkt_primitives *srcdst)
{
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  
  return modulo %= config.sql_cache_entries;
}

int MY_cache_dbop(MYSQL *db_desc, const struct db_cache *cache_elem, const int num_primitives)
{
  char *ptr_values, *ptr_where;
  int num=0, ret=0;

  /* constructing sql query */
  ptr_where = where_clause;
  ptr_values = values_clause; 
  memset(where_clause, 0, sizeof(where_clause));
  memset(values_clause, 0, sizeof(values_clause));
  while (num < num_primitives) {
    (*where[num].handler)(cache_elem, num, &ptr_values, &ptr_where);
    num++;
  }
  
  snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter);
  strncat(sql_data, where_clause, SPACELEFT(sql_data));

  /* sending UPDATE query */
  if (!config.sql_dont_try_update) {
    ret = mysql_query(db_desc, sql_data);
    if (ret) {
      Log(LOG_DEBUG, "FAILED query follows:\n%s\n", sql_data);
      Log(LOG_ERR, "ERROR: %s\n\n", mysql_error(db_desc));
      if (mysql_errno(db_desc) == 1062) return FALSE; /* not signalling duplicate entry problems */ 
      else return ret; 
    }
  }

  if (config.sql_dont_try_update || (mysql_affected_rows(db_desc) == 0)) {
    /* UPDATE failed, trying with an INSERT query */ 
    strncpy(sql_data, insert_clause, sizeof(sql_data));
    snprintf(ptr_values, SPACELEFT(values_clause), ", %d, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter);
    strncat(sql_data, values_clause, SPACELEFT(sql_data));
    ret = mysql_query(db_desc, sql_data);
    if (ret) {
      Log(LOG_DEBUG, "FAILED query follows:\n%s\n", sql_data);
      Log(LOG_ERR, "ERROR: %s\n\n", mysql_error(db_desc));
      if (mysql_errno(db_desc) == 1062) return FALSE; /* not signalling duplicate entry problems */
      else return ret;
    }
  }

  if (config.debug) Log(LOG_DEBUG, "%s\n\n", sql_data);

  return ret;
}

void MY_cache_insert(struct pkt_data *data, struct insert_data *idata) 
{
  int chances = 2;
  unsigned int modulo = idata->modulo;
  unsigned long int basetime = idata->basetime;
  struct pkt_primitives *srcdst = &data->primitives;

  while ((basetime > data->pkt_time) && (data->pkt_time > 0)) basetime -= idata->timeslot;

  start:
  if (memcmp(&cache[idata->modulo], srcdst, sizeof(struct pkt_primitives)) != 0) { 
    /* aliasing of entries: if there is some valid value,
       we trap a live sql query; otherwise we put this entry
       in the queue of pending sql queries */
    if (cache[idata->modulo].valid == TRUE) { 
      /* chances are a trivial implementation of a n-way associative cache */
      if (chances == 2) {
        idata->modulo++;
        idata->modulo %= config.sql_cache_entries;
        chances--;
        goto start;
      }
      else if (chances == 1) {
        if (modulo) {
	  modulo--;
	  modulo %= config.sql_cache_entries;
          idata->modulo = modulo;
	}
	else idata->modulo = config.sql_cache_entries-1;
        chances--;

        goto start;
      }

      if (config.debug) Log(LOG_DEBUG, "*** Entry aliasing ***\n");
      MY_handle_collision(&cache[idata->modulo]);
    }
    else {
      queries_queue[qq_ptr] = &cache[idata->modulo];
      qq_ptr++;
    }

    /* we add the new entry in the cache */
    memcpy(&cache[idata->modulo], srcdst, sizeof(struct pkt_primitives));
    cache[idata->modulo].packet_counter = ntohl(data->pkt_num);
    cache[idata->modulo].bytes_counter = ntohl(data->pkt_len);
    cache[idata->modulo].valid = TRUE;
    cache[idata->modulo].basetime = basetime;
  }
  else {
    if (cache[idata->modulo].valid == TRUE) {
      /* additional check: time */
      if ((cache[idata->modulo].basetime < basetime) && (config.sql_history)) {
	if (config.debug) Log(LOG_DEBUG, "*** Entry aliasing ***\n");
	MY_handle_collision(&cache[idata->modulo]);
	cache[idata->modulo].packet_counter = ntohl(data->pkt_num); 
	cache[idata->modulo].bytes_counter =  ntohl(data->pkt_len);
	cache[idata->modulo].basetime = basetime;
      }
      /* additional check: would counters overflow ? */
      else if ((cache[idata->modulo].packet_counter > UINT32TMAX) ||
	       (cache[idata->modulo].bytes_counter > UINT32TMAX)) {
	MY_handle_collision(&cache[idata->modulo]);
        cache[idata->modulo].packet_counter = ntohl(data->pkt_num);
        cache[idata->modulo].bytes_counter = ntohl(data->pkt_len);
	cache[idata->modulo].basetime = basetime;
      }
      else {
        /* everything is ok; summing counters */
        cache[idata->modulo].packet_counter += ntohl(data->pkt_num);
        cache[idata->modulo].bytes_counter += ntohl(data->pkt_len);
      }
    }
    else {
      /* entry invalidated; restarting counters */
      cache[idata->modulo].packet_counter = ntohl(data->pkt_num);
      cache[idata->modulo].bytes_counter = ntohl(data->pkt_len);
      cache[idata->modulo].valid = TRUE;
      cache[idata->modulo].basetime = basetime;
      queries_queue[qq_ptr] = &cache[idata->modulo];
      qq_ptr++;
    }
  }
}

void MY_cache_purge(struct db_cache *queue[], int index, const int num_primitives, int ptr)
{
  unsigned char *qptr = (unsigned char *) *queue;
  struct logfile lf;
  int j;

  memset(&lf, 0, sizeof(struct logfile));

  if (config.debug) Log(LOG_DEBUG, "*** Purging cache - START ***\n");
  MY_Lock(&p, &b, &lf); 

  if (ptr) for (j = 0; j < index; j++) MY_Query(&p, &b, &lf, queue[j], num_primitives);
  else {
    for (j = 0; j < index; j++) {
      MY_Query(&p, &b, &lf, (struct db_cache *) qptr, num_primitives); 
      qptr += dbc_size;
    }
  }

  /* rewinding stuff */
  MY_Unlock(&p, &b, &lf);
  if ((lf.fail) || (b.fail)) Log(LOG_ALERT, "ALERT: recovery for MySQL daemon failed.\n");
  
  if (config.debug) Log(LOG_DEBUG, "*** Purging cache - END ***\n");
}

int MY_cache_flush(struct db_cache *queue[], int index, int ptr)
{
  unsigned char *qptr = (unsigned char *) *queue;
  int j;

  if (ptr) for (j = 0; j < index; j++) queue[j]->valid = FALSE;
  else {
    for (j = 0; j < index; j++) {
      ((struct db_cache *)qptr)->valid = FALSE; 
      qptr += dbc_size;
    }
  }
  index = 0;
  
  return index;
}

void MY_handle_collision(struct db_cache *elem)
{
  if (cq_ptr < cq_size) {
    memcpy(&collision_queue[cq_ptr], elem, dbc_size);
    cq_ptr++;
  }
  else {
    /* purging collision queue */
    switch (fork()) {
    case 0: /* Child */
      config.sql_dont_try_update = FALSE;
      MY_cache_purge(&collision_queue, cq_ptr, num_primitives, FALSE);
      exit(0);
    default: /* Parent */
      cq_ptr = MY_cache_flush(&collision_queue, cq_ptr, FALSE);
      break;
    }

    memcpy(&collision_queue[cq_ptr], elem, dbc_size);
    cq_ptr++;
  }
}

int MY_evaluate_history(int primitive)
{
  if (config.sql_history) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(where[primitive].string, "FROM_UNIXTIME(%d) = ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "stamp_inserted", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "stamp_updated, stamp_inserted", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "now(), FROM_UNIXTIME(%d)", SPACELEFT(values[primitive].string));

    where[primitive].type = values[primitive].type = TIMESTAMP;
    values[primitive].handler = where[primitive].handler = count_timestamp_handler;
    primitive++;
  }

  return primitive;
}

int MY_evaluate_primitives(int primitive)
{
  register unsigned long int what_to_count=0;
  register unsigned long int fakes=0;
  short int assume_custom_table = FALSE; 

  if (config.sql_optimize_clauses) {
    what_to_count = config.what_to_count;
    assume_custom_table = TRUE;
  }
  else {
    /* we are requested to avoid optimization;
       then we'll construct an all-true "what
       to count" bitmap */ 
    if (config.what_to_count & COUNT_SRC_MAC) what_to_count |= COUNT_SRC_MAC;
    else fakes |= FAKE_SRC_MAC;
    if (config.what_to_count & COUNT_DST_MAC) what_to_count |= COUNT_DST_MAC;
    else fakes |= FAKE_DST_MAC;

    if (config.what_to_count & COUNT_SRC_HOST) what_to_count |= COUNT_SRC_HOST;
    else fakes |= FAKE_SRC_HOST;
    if (config.what_to_count & COUNT_DST_HOST) what_to_count |= COUNT_DST_HOST;
    else fakes |= FAKE_DST_HOST;

    what_to_count |= COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_IP_PROTO|COUNT_ID|COUNT_VLAN;
  }

  /* 1st part: arranging pointers to an opaque structure and 
     composing the static selection (WHERE) string */

  if (what_to_count & COUNT_SRC_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_MAC;
    values[primitive].handler = where[primitive].handler = count_src_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_MAC;
    values[primitive].handler = where[primitive].handler = count_dst_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_VLAN) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_VLAN) {
        Log(LOG_ERR, "ERROR: The use of VLAN accounting requires SQL table v2. Exiting.\n");
        exit(1);
      }
      else what_to_count ^= COUNT_VLAN;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "vlan", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%d", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "vlan=%d", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_VLAN;
      values[primitive].handler = where[primitive].handler = count_vlan_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_SRC_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_HOST;
    values[primitive].handler = where[primitive].handler = count_src_host_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_HOST;
    values[primitive].handler = where[primitive].handler = count_dst_host_handler;
    primitive++;
  }

  if (what_to_count & COUNT_SRC_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "src_port", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%d", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "src_port=%d", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_PORT;
    values[primitive].handler = where[primitive].handler = count_src_port_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "dst_port", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%d", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "dst_port=%d", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_PORT;
    values[primitive].handler = where[primitive].handler = count_dst_port_handler;
    primitive++;
  }

  if (what_to_count & COUNT_IP_PROTO) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_proto", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_proto=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_IP_PROTO;
    values[primitive].handler = where[primitive].handler = MY_count_ip_proto_handler;
    primitive++;
  }

  if (what_to_count & COUNT_ID) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_ID) {
	Log(LOG_ERR, "ERROR: The use of IDs requires SQL table v2. Exiting.\n");
        exit(1);	
      }
      else what_to_count ^= COUNT_ID;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "agent_id", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%d", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "agent_id=%d", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_ID;
      values[primitive].handler = where[primitive].handler = count_id_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_SRC_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_SRC_MAC;
    values[primitive].handler = where[primitive].handler = fake_mac_handler;
    primitive++;
  }

  if (fakes & FAKE_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_DST_MAC;
    values[primitive].handler = where[primitive].handler = fake_mac_handler;
    primitive++;
  }

  if (fakes & FAKE_SRC_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_SRC_HOST;
    values[primitive].handler = where[primitive].handler = fake_host_handler;
    primitive++;
  }

  if (fakes & FAKE_DST_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_DST_HOST;
    values[primitive].handler = where[primitive].handler = fake_host_handler;
    primitive++;
  }

  return primitive;
}

int MY_compose_static_queries()
{
  int primitives=0;

  /* "INSERT INTO ... VALUES ... " and "... WHERE ..." stuff */
  strncpy(where[primitives].string, " WHERE ", sizeof(where[primitives].string));
  snprintf(insert_clause, sizeof(insert_clause), "INSERT INTO %s (", config.sql_table);
  strncpy(values[primitives].string, " VALUES (", sizeof(values[primitives].string));
  primitives = MY_evaluate_history(primitives);
  primitives = MY_evaluate_primitives(primitives);
  strncat(insert_clause, ", packets, bytes)", SPACELEFT(insert_clause));

  /* "LOCK ..." stuff */
  snprintf(lock_clause, sizeof(lock_clause), "LOCK TABLES %s WRITE", config.sql_table);
  strncpy(unlock_clause, "UNLOCK TABLES", sizeof(unlock_clause));

  /* "UPDATE ... SET ..." stuff */
  snprintf(update_clause, sizeof(update_clause), "UPDATE %s ", config.sql_table);
  strncat(update_clause, "SET packets=packets+%d, bytes=bytes+%lu", SPACELEFT(update_clause));
  if (config.sql_history) strncat(update_clause, ", stamp_updated=now()", SPACELEFT(update_clause));

  return primitives;
}

void MY_exit_gracefully(int signum)
{
  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  if (config.debug) Log(LOG_DEBUG, "*** Purging MySQL queries queue ***\n");
  if (config.syslog) closelog();

  memset(&p, 0, sizeof(p));
  memset(&b, 0, sizeof(b));

  if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  if (cq_ptr) MY_cache_purge(&collision_queue, cq_ptr, num_primitives, FALSE);
  MY_cache_purge(queries_queue, qq_ptr, num_primitives, TRUE);

  if (!p.fail) mysql_close(&p.desc);
  else if (b.connected) mysql_close(&b.desc);

  exit(0); 
}

void MY_Lock(struct DBdesc *p, struct DBdesc *b, struct logfile *lf)
{
  if (!p->fail) {
    if (mysql_query(&p->desc, lock_clause)) goto recovery; 
    else return;
  }
  else return; 

  recovery:
  Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  if (config.sql_backup_host || config.sql_recovery_logfile) {
    p->fail = TRUE; 
    p->connected = FALSE;
  }
}

void MY_Query(struct DBdesc *p, struct DBdesc *b, struct logfile *lf, const struct db_cache *elem, int num_primitives)
{
  if (!p->fail) {
    if (MY_cache_dbop(&p->desc, elem, num_primitives)) goto recovery; 
    else return;
  }
  else goto take_action;

  recovery:
  Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  if (config.sql_backup_host || config.sql_recovery_logfile) {
    p->fail = TRUE;
    p->connected = FALSE;
  }

  take_action:
  if (config.sql_backup_host) {
    if (!b->fail) {
      if (!b->connected) {
        if (!MY_DB_Connect(b, config.sql_backup_host)) b->fail = TRUE;
        else b->connected = TRUE;
      }
      if (!b->locked) {
        if (mysql_query(&b->desc, lock_clause)) {
	  b->fail = TRUE;
	  b->connected = FALSE;
	}
        else b->locked = TRUE;
      }
      if (MY_cache_dbop(&b->desc, elem, num_primitives)) {
	b->fail = TRUE; 
	b->connected = FALSE;
      }
    }
  }
  if (config.sql_recovery_logfile) {
    if (!lf->fail) {
      if (!lf->open) {
        lf->file = MY_file_open(config.sql_recovery_logfile, "a");
        if (!lf->file) lf->fail = TRUE;
        else lf->open = TRUE;
      }
      if (!lf->fail) fwrite(elem, sizeof(struct db_cache), 1, lf->file);
    }
  }
}

void MY_Unlock(struct DBdesc *p, struct DBdesc *b, struct logfile *lf)
{
  if (!p->fail) mysql_query(&p->desc, unlock_clause);
  else {
    if (config.sql_backup_host) {
      if ((!b->fail) && (b->locked)) {
	mysql_query(&b->desc, unlock_clause);
	b->locked = FALSE;
      }
    }
    if (config.sql_recovery_logfile) {
      if (lf->file) {
	flock(fileno(lf->file), LOCK_UN);
	fclose(lf->file);
      }
    }
  }
}

FILE *MY_file_open(const char *path, const char *mode)
{
  struct stat st;
  struct logfile_header lh;
  FILE *f;
  int ret;

  ret = stat(path, &st);
  if (ret < 0) {
    memset(&lh, 0, sizeof(struct logfile_header));
    strlcpy(lh.sql_db, config.sql_db, DEF_HDR_FIELD_LEN);
    strlcpy(lh.sql_table, config.sql_table, DEF_HDR_FIELD_LEN);
    strlcpy(lh.sql_user, config.sql_user, DEF_HDR_FIELD_LEN);
    if (config.sql_host) strlcpy(lh.sql_host, config.sql_host, DEF_HDR_FIELD_LEN);
    else strlcpy(lh.sql_host, "localhost", DEF_HDR_FIELD_LEN);
    lh.sql_table_version = config.sql_table_version;
    lh.sql_optimize_clauses = config.sql_optimize_clauses;
    lh.sql_history = config.sql_history;
    lh.what_to_count = config.what_to_count;
    lh.magic = MAGIC;

    f = fopen(path, "a");
    if (flock(fileno(f), LOCK_EX)) Log(LOG_ALERT, "ALERT: Unable to obtain lock of %s\n", path); 
    if (f) fwrite(&lh, sizeof(lh), 1, f);
  }
  else {
    f = fopen(path, "r");
    if (flock(fileno(f), LOCK_EX)) Log(LOG_ALERT, "ALERT: Unable to obtain lock of %s\n", path); 
    if (f) {
      fread(&lh, sizeof(lh), 1, f);
      if (lh.magic == MAGIC) freopen(path, "a", f);
      else {
	Log(LOG_ALERT, "ALERT: Invalid magic number: %s. Take countermeasures !\n", path);
	flock(fileno(f), LOCK_UN);
	fclose(f);
	return NULL;
      }
    }
  }

  return f;
}

int MY_DB_Connect(struct DBdesc *db, char *host)
{
  int ret = 0;

  mysql_init(&db->desc);
  db->desc.reconnect = TRUE;
  if (!mysql_real_connect(&db->desc, host, config.sql_user, config.sql_passwd, config.sql_db, 0, NULL, 0)) {
    if (config.sql_backup_host || config.sql_recovery_logfile) db->fail = TRUE;
    db->connected = FALSE;
    ret = FALSE;
  }
  else {
    db->connected = TRUE; 
    ret = TRUE;
  }

  return ret;
}

int MY_Exec(char *filename)
{
  int pid;

  switch (pid = vfork()) {
  case -1:
    return -1;
  case 0:
    execv(filename, NULL); 
    exit(0);
  }
}
