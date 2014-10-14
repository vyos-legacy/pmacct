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

#define __MYSQL_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "mysql_plugin.h"
#include "net_aggr.h"
#include "ports_aggr.h"
#include "util.h"
#include "crc32.c"
#include "sql_common_m.c"

/* Functions */
void mysql_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct networks_table nt;
  struct networks_cache nc;
  struct ports_table pt;
  unsigned char *pipebuf;
  char mysql_user[] = "pmacct";
  char mysql_pwd[] = "arealsmartpwd";
  char mysql_db[] = "pmacct"; 
  char mysql_table[] = "acct";
  char mysql_table_v2[] = "acct_v2";
  char mysql_table_v3[] = "acct_v3";
  struct pollfd pfd;
  struct insert_data idata;
  time_t t, now, refresh_deadline;
  int timeout;
  int ret, num;
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
  signal(SIGCHLD, SIG_IGN); 

  if (!config.sql_refresh_time)
    config.sql_refresh_time = DEFAULT_DB_REFRESH_TIME;

  if (!config.sql_table_version)
    config.sql_table_version = DEFAULT_SQL_TABLE_VERSION;

  timeout = config.sql_refresh_time*1000; /* dirty */

  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET|COUNT_SUM_AS))
    insert_func = MY_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = MY_sum_port_insert;
  else insert_func = MY_cache_insert;

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);

  memset(sql_data, 0, sizeof(sql_data));
  memset(lock_clause, 0, sizeof(lock_clause));
  memset(unlock_clause, 0, sizeof(unlock_clause));
  memset(update_clause, 0, sizeof(update_clause));
  memset(insert_clause, 0, sizeof(insert_clause));
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));
  memset(&lru_head, 0, sizeof(lru_head));
  lru_tail = &lru_head;

  if (!config.sql_cache_entries) config.sql_cache_entries = CACHE_ENTRIES;
  qq_ptr = 0;
  qq_size = config.sql_cache_entries+(config.sql_refresh_time*REASONABLE_NUMBER);
  pp_size = sizeof(struct pkt_primitives);
  dbc_size = sizeof(struct db_cache);

  pipebuf = (unsigned char *) malloc(config.buffer_size);
  cache = (struct db_cache *) malloc(config.sql_cache_entries*sizeof(struct db_cache)); 
  queries_queue = (struct db_cache **) malloc(qq_size*sizeof(struct db_cache *));

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  /* searching for user supplied values */ 
  if (!config.sql_user) config.sql_user = mysql_user; 
  if (!config.sql_db) config.sql_db = mysql_db;
  if (!config.sql_passwd) config.sql_passwd = mysql_pwd; 
  if (!config.sql_table) {
    if (config.sql_table_version == 3) config.sql_table = mysql_table_v3;
    else if (config.sql_table_version == 2) config.sql_table = mysql_table_v2;
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
    else if (config.sql_history == COUNT_WEEKLY)
      idata.timeslot = config.sql_history_howmany*86400*7;
    else if (config.sql_history == COUNT_MONTHLY) {
      idata.basetime = roundoff_time(idata.basetime, "d"); /* resetting day of month */
      idata.timeslot = calc_monthly_timeslot(idata.basetime, config.sql_history_howmany, ADD);
    }

    /* round off stuff */
    t = roundoff_time(idata.basetime, config.sql_history_roundoff);
    while ((t+idata.timeslot) < idata.basetime) {
      t += idata.timeslot; 
      if (config.sql_history == COUNT_MONTHLY)
	idata.timeslot = calc_monthly_timeslot(t, config.sql_history_howmany, ADD);
    }
    idata.basetime = t;
  }

  /* sql triggers time init: deadline; if a trigger exec is specified but no
     time is supplied, use 'sql_refresh_time' as interval; this will result in
     a trigger being executed each time data is purged into the DB */
  if (config.sql_trigger_exec) {
    time_t deadline;

    deadline = now;
    if (config.sql_trigger_time == COUNT_MINUTELY)
      idata.t_timeslot = config.sql_trigger_time_howmany*60;
    else if (config.sql_trigger_time == COUNT_HOURLY)
      idata.t_timeslot = config.sql_trigger_time_howmany*3600;
    else if (config.sql_trigger_time == COUNT_DAILY)
      idata.t_timeslot = config.sql_trigger_time_howmany*86400;
    else if (config.sql_trigger_time == COUNT_WEEKLY)
      idata.t_timeslot = config.sql_trigger_time_howmany*86400*7;
    else if (config.sql_trigger_time == COUNT_MONTHLY) {
      deadline = roundoff_time(deadline, "d"); /* resetting day of month */
      idata.t_timeslot = calc_monthly_timeslot(deadline, config.sql_trigger_time_howmany, ADD);
    }
    else idata.t_timeslot = config.sql_refresh_time; 

    /* round off stuff */
    t = roundoff_time(deadline, config.sql_history_roundoff);
    while ((t+idata.t_timeslot) < deadline) {
      t += idata.t_timeslot;
      if (config.sql_trigger_time == COUNT_MONTHLY)
	idata.t_timeslot = calc_monthly_timeslot(t, config.sql_trigger_time_howmany, ADD);
    }
    idata.triggertime = t;

    /* adding a trailer timeslot: it's a deadline not a basetime */
    idata.triggertime += idata.t_timeslot; 
    if (config.sql_trigger_time == COUNT_MONTHLY)
      idata.t_timeslot = calc_monthly_timeslot(t, config.sql_trigger_time_howmany, ADD);
  }

  /* sql_refresh time init: deadline */
  refresh_deadline = now; 
  t = roundoff_time(refresh_deadline, config.sql_history_roundoff);
  while ((t+config.sql_refresh_time) < refresh_deadline) t += config.sql_refresh_time;
  refresh_deadline = t;
  refresh_deadline += (config.sql_refresh_time+config.sql_startup_delay); /* it's a deadline not a basetime */

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* building up static SQL clauses */
  idata.num_primitives = MY_compose_static_queries();
  num_primitives = idata.num_primitives; 

  /* handling logfile template stuff */
  te = build_template(&th);
  set_template_funcs(&th, te);
  INIT_BUF(logbuf);

  /* handling purge preprocessor */
  set_preprocess_funcs(config.sql_preprocess, &prep); 

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.sql_cache_entries*sizeof(struct db_cache));
  memset(queries_queue, 0, qq_size*sizeof(struct db_cache *));
  memset(&bed, 0, sizeof(struct BE_descs));

  /* setting up environment variables */
  SQL_SetENV();

  /* linking backend descriptors */
  bed.p = &p; 
  bed.b = &b;

  /* plugin main loop */
  for(;;) {
    poll_again:
#if defined (HAVE_MMAP)
    status->wakeup = TRUE;
#endif
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    idata.now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      switch (fork()) {
      case 0: /* Child */
	/* we have to ignore signals to avoid loops:
	   because we are already forked */
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	memset(&p, 0, sizeof(p));
	memset(&b, 0, sizeof(b));

	if (qq_ptr) {
          if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
          MY_cache_purge(queries_queue, qq_ptr, &idata);

	  if (!p.fail) mysql_close(&p.desc);
	  else if (b.connected) mysql_close(&b.desc);
	}

	if (config.sql_trigger_exec) {
	  if (idata.now > idata.triggertime) MY_Exec(config.sql_trigger_exec);
	}
	  
        exit(0);
      default: /* Parent */
	if (qq_ptr) qq_ptr = MY_cache_flush(queries_queue, qq_ptr);
	refresh_deadline += config.sql_refresh_time; 
	if (idata.now > idata.triggertime) {
	  idata.triggertime  += idata.t_timeslot;
	  if (config.sql_trigger_time == COUNT_MONTHLY)
	    idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	}
        break;
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
	idata.now = time(NULL); 
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
            Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
            Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
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
      if (idata.now > refresh_deadline) {
        switch (fork()) {
        case 0: /* Child */
          /* we have to ignore signals to avoid loops:
             because we are already forked */
          signal(SIGINT, SIG_IGN);
          signal(SIGHUP, SIG_IGN);

          memset(&p, 0, sizeof(p));
          memset(&b, 0, sizeof(b));

	  if (qq_ptr) {
            if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
            MY_cache_purge(queries_queue, qq_ptr, &idata);

	    if (!p.fail) mysql_close(&p.desc);
	    else if (b.connected) mysql_close(&b.desc);
	  }

	  if (config.sql_trigger_exec) {
	    if (idata.now > idata.triggertime) MY_Exec(config.sql_trigger_exec);
	  }

          exit(0);
        default: /* Parent */
          if (qq_ptr) qq_ptr = MY_cache_flush(queries_queue, qq_ptr);
	  refresh_deadline += config.sql_refresh_time; 
          if (idata.now > idata.triggertime) {
	    idata.triggertime  += idata.t_timeslot;
	    if (config.sql_trigger_time == COUNT_MONTHLY)
	      idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	  }
          break;
        }
      } 
      else {
	if (config.sql_trigger_exec) {
	  if (idata.now > idata.triggertime) {
	    MY_Exec(config.sql_trigger_exec); 
	    idata.triggertime += idata.t_timeslot;
	    if (config.sql_trigger_time == COUNT_MONTHLY)
	      idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	  }
	}
      }

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));
      if (idata.now > (idata.basetime + idata.timeslot)) {
	idata.basetime += idata.timeslot;
	if (config.sql_history == COUNT_MONTHLY)
	  idata.timeslot = calc_monthly_timeslot(idata.basetime, config.sql_history_howmany, ADD);
      }

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives);

	if (config.ports_file) {
	  if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
	  if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
	}

	(*insert_func)(data, &idata);
	
	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) data++;
      }
#if defined (HAVE_MMAP)
      goto read_data;
#endif
    }
  }
}

void MY_cache_modulo(struct pkt_primitives *srcdst, struct insert_data *idata)
{
  idata->hash = cache_crc32((unsigned char *)srcdst, pp_size);
  idata->modulo = idata->hash % config.sql_cache_entries;
}

int MY_cache_dbop(MYSQL *db_desc, const struct db_cache *cache_elem, struct insert_data *idata)
{
  char *ptr_values, *ptr_where;
  int num=0, ret=0;

  /* constructing sql query */
  ptr_where = where_clause;
  ptr_values = values_clause; 
  memset(where_clause, 0, sizeof(where_clause));
  memset(values_clause, 0, sizeof(values_clause));
  while (num < idata->num_primitives) {
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
    snprintf(ptr_values, SPACELEFT(values_clause), ", %u, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter);
    strncat(sql_data, values_clause, SPACELEFT(sql_data));
    ret = mysql_query(db_desc, sql_data);
    if (ret) {
      Log(LOG_DEBUG, "FAILED query follows:\n%s\n", sql_data);
      Log(LOG_ERR, "ERROR: %s\n\n", mysql_error(db_desc));
      if (mysql_errno(db_desc) == 1062) return FALSE; /* not signalling duplicate entry problems */
      else return ret;
    }
    idata->iqn++;
  }
  else idata->uqn++;

  if (config.debug) Log(LOG_DEBUG, "%s\n\n", sql_data);

  return ret;
}

void MY_cache_insert(struct pkt_data *data, struct insert_data *idata) 
{
  unsigned int modulo;
  unsigned long int basetime = idata->basetime, timeslot = idata->timeslot;
  struct pkt_primitives *srcdst = &data->primitives;
  struct db_cache *Cursor, *newElem, *SafePtr = NULL, *staleElem = NULL;

  MY_cache_modulo(&data->primitives, idata);
  modulo = idata->modulo;

  if (data->pkt_time && config.sql_history) {
    while (basetime > data->pkt_time) {
      if (config.sql_history != COUNT_MONTHLY) basetime -= timeslot;
      else {
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, SUB);
        basetime -= timeslot;
      }
    }
    while ((basetime+timeslot) < data->pkt_time) {
      if (config.sql_history != COUNT_MONTHLY) basetime += timeslot;
      else {
        basetime += timeslot;
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, ADD);
      }
    }
  }

  /* housekeeping */
  if (lru_head.lru_next && ((idata->now-lru_head.lru_next->lru_tag) > RETIRE_M*config.sql_refresh_time))
    RetireElem(lru_head.lru_next);

  Cursor = &cache[idata->modulo];

  start:
  if (idata->hash != Cursor->signature) {
    if (Cursor->valid == TRUE) {
      follow_chain:
      if (Cursor->next) {
        Cursor = Cursor->next;
        goto start;
      }
      else {
        if (lru_head.lru_next && ((idata->now-lru_head.lru_next->lru_tag) > STALE_M*config.sql_refresh_time)) {
          newElem = lru_head.lru_next;
          ReBuildChain(Cursor, newElem);
          Cursor = newElem;
          goto insert; /* we have successfully reused a stale element */
        }
        else {
          newElem = (struct db_cache *) malloc(sizeof(struct db_cache));
          if (newElem) {
            memset(newElem, 0, sizeof(struct db_cache));
            BuildChain(Cursor, newElem);
            Cursor = newElem;
            goto insert; /* creating a new element */
          }
          else goto safe_action; /* we should have finished memory */
        }
      }
    }
    else goto insert; /* we found a no more valid entry; let's insert here our data */
  }
  else {
    if (Cursor->valid == TRUE) {
      /* additional check: pkt_primitives */
      if (!memcmp(Cursor, srcdst, sizeof(struct pkt_primitives))) {
        /* additional check: time */
        if ((Cursor->basetime < basetime) && (config.sql_history)) {
          if (!staleElem && Cursor->chained) staleElem = Cursor;
          goto follow_chain;
        }
        /* additional check: counters overflow */
        else if ((Cursor->packet_counter > UINT32TMAX) || (Cursor->bytes_counter > UINT32TMAX)) {
          if (!staleElem && Cursor->chained) staleElem = Cursor;
          goto follow_chain;
        }
        else goto update;
      }
      else goto follow_chain;
    }
    else goto insert;
  }

  insert:
  if (qq_ptr < qq_size) {
    queries_queue[qq_ptr] = Cursor;
    qq_ptr++;
  }
  else SafePtr = Cursor;

  /* we add the new entry in the cache */
  memcpy(Cursor, srcdst, sizeof(struct pkt_primitives));
  Cursor->packet_counter = ntohl(data->pkt_num);
  Cursor->bytes_counter = ntohl(data->pkt_len);
  Cursor->valid = TRUE;
  Cursor->basetime = basetime;
  Cursor->lru_tag = idata->now;
  Cursor->signature = idata->hash;
  if (Cursor->chained) AddToLRUTail(Cursor); /* we cannot reuse not-malloc()'ed elements */
  if (SafePtr) goto safe_action;
  if (staleElem) SwapChainedElems(Cursor, staleElem);
  return;

  update:
  Cursor->packet_counter += ntohl(data->pkt_num);
  Cursor->bytes_counter += ntohl(data->pkt_len);
  return;

  safe_action:
  Log(LOG_DEBUG, "DEBUG: purging process (CAUSE: safe action)\n");

  switch (fork()) {
  case 0: /* Child */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    memset(&p, 0, sizeof(p));
    memset(&b, 0, sizeof(b));

    if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");

    MY_cache_purge(queries_queue, qq_ptr, idata);
    if (!p.fail) mysql_close(&p.desc);
    else if (b.connected) mysql_close(&b.desc);
    exit(0);
  default: /* Parent */
    qq_ptr = MY_cache_flush(queries_queue, qq_ptr);
    break;
  }
  if (SafePtr) {
    queries_queue[qq_ptr] = Cursor;
    qq_ptr++;
  }
  else {
    Cursor = &cache[idata->modulo];
    goto start;
  }
}

void MY_cache_purge(struct db_cache *queue[], int index, struct insert_data *idata)
{
  struct logfile lf;
  time_t start;
  int j, stop;

  bed.lf = &lf;
  memset(&lf, 0, sizeof(struct logfile));

  for (j = 0, stop = 0; (!stop) && preprocess_funcs[j]; j++)
    stop = preprocess_funcs[j](queue, &index); 
  idata->ten = index;

  if (config.debug) {
    Log(LOG_DEBUG, "*** Purging cache - START ***\n");
    start = time(NULL);
  }
  MY_Lock(&bed); 

  for (j = 0; j < index; j++) {
    if (queue[j]->valid) MY_Query(&bed, queue[j], idata);
  }

  /* rewinding stuff */
  MY_Unlock(&bed);
  if ((lf.fail) || (b.fail)) Log(LOG_ALERT, "ALERT: recovery for MySQL daemon failed.\n");
  
  if (config.debug) {
    idata->elap_time = time(NULL)-start;
    Log(LOG_DEBUG, "*** Purging cache - END (QN: %u, ET: %u) ***\n", index, idata->elap_time); 
  }

  if (config.sql_trigger_exec) {
    if (!config.debug) idata->elap_time = time(NULL)-start;

    if (preprocess_funcs[0]) {
      for (j = 0; j < index; j++) {
	if (queue[j]->valid > 0) idata->een++;
      }
    }
    SQL_SetENV_child(idata);
  }
}

int MY_cache_flush(struct db_cache *queue[], int index)
{
  int j;

  for (j = 0; j < index; j++) queue[j]->valid = FALSE;
  index = 0;
  
  return index;
}

int MY_evaluate_history(int primitive)
{
  if (config.sql_history) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(where[primitive].string, "FROM_UNIXTIME(%u) = ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "stamp_inserted", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "stamp_updated, stamp_inserted", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "now(), FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));

    where[primitive].type = values[primitive].type = TIMESTAMP;
    values[primitive].handler = where[primitive].handler = count_timestamp_handler;
    primitive++;
  }

  return primitive;
}

int MY_evaluate_primitives(int primitive)
{
  u_int32_t what_to_count = 0, fakes = 0;
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

    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) what_to_count |= COUNT_SRC_HOST;
    else if (config.what_to_count & COUNT_SRC_AS) what_to_count |= COUNT_SRC_AS;
    else if (config.what_to_count & COUNT_SUM_HOST) what_to_count |= COUNT_SUM_HOST;
    else if (config.what_to_count & COUNT_SUM_NET) what_to_count |= COUNT_SUM_NET;
    else if (config.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS;
    else fakes |= FAKE_SRC_HOST;

    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) what_to_count |= COUNT_DST_HOST;
    else if (config.what_to_count & COUNT_DST_AS) what_to_count |= COUNT_DST_AS;
    else fakes |= FAKE_DST_HOST;

    if (config.what_to_count & COUNT_SUM_PORT) what_to_count |= COUNT_SUM_PORT;

    what_to_count |= COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_IP_PROTO|COUNT_ID|COUNT_VLAN|COUNT_IP_TOS;
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
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "vlan=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_VLAN;
      values[primitive].handler = where[primitive].handler = count_vlan_handler;
      primitive++;
    }
  }

  if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
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

  if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
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

  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_AS;
    values[primitive].handler = where[primitive].handler = count_src_as_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_AS;
    values[primitive].handler = where[primitive].handler = count_dst_as_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "src_port", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "src_port=%u", SPACELEFT(where[primitive].string));
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
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "dst_port=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_PORT;
    values[primitive].handler = where[primitive].handler = count_dst_port_handler;
    primitive++;
  }

  if (what_to_count & COUNT_IP_TOS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 3) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_TOS) {
        Log(LOG_ERR, "ERROR: The use of ToS/DSCP accounting requires SQL table v3. Exiting.\n");
        exit(1);
      }
      else what_to_count ^= COUNT_IP_TOS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "tos", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tos=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_IP_TOS;
      values[primitive].handler = where[primitive].handler = count_ip_tos_handler;
      primitive++;
    }
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
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "agent_id=%u", SPACELEFT(where[primitive].string));
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
  strncat(update_clause, "SET packets=packets+%u, bytes=bytes+%lu", SPACELEFT(update_clause));
  if (config.sql_history) strncat(update_clause, ", stamp_updated=now()", SPACELEFT(update_clause));

  return primitives;
}

void MY_exit_gracefully(int signum)
{
  struct insert_data idata;
  
  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  if (config.debug) Log(LOG_DEBUG, "*** Purging MySQL queries queue ***\n");
  if (config.syslog) closelog();

  memset(&p, 0, sizeof(p));
  memset(&b, 0, sizeof(b));

  memset(&idata, 0, sizeof(idata));
  idata.num_primitives = num_primitives;

  if (!MY_DB_Connect(&p, config.sql_host)) Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  MY_cache_purge(queries_queue, qq_ptr, &idata);

  if (!p.fail) mysql_close(&p.desc);
  else if (b.connected) mysql_close(&b.desc);

  exit(0); 
}

void MY_Lock(struct BE_descs *bed)
{
  if (!bed->p->fail) {
    if (mysql_query(&bed->p->desc, lock_clause)) goto recovery; 
    else return;
  }
  else return; 

  recovery:
  Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  if (config.sql_backup_host || config.sql_recovery_logfile) {
    bed->p->fail = TRUE; 
    bed->p->connected = FALSE;
  }
}

void MY_Query(struct BE_descs *bed, const struct db_cache *elem, struct insert_data *idata)
{
  if ((!bed->p->fail) && (elem->valid > 0)) {
    if (MY_cache_dbop(&bed->p->desc, elem, idata)) goto recovery; 
    else return;
  }
  else goto take_action;

  recovery:
  Log(LOG_ALERT, "ALERT: MySQL daemon failed.\n");
  if (config.sql_backup_host || config.sql_recovery_logfile) {
    bed->p->fail = TRUE;
    bed->p->connected = FALSE;
  }

  take_action:
  if (config.sql_backup_host) {
    if (!bed->b->fail) {
      if (!bed->b->connected) {
        if (!MY_DB_Connect(bed->b, config.sql_backup_host)) bed->b->fail = TRUE;
        else bed->b->connected = TRUE;
        if (mysql_query(&bed->b->desc, lock_clause)) {
	  bed->b->fail = TRUE;
	  bed->b->connected = FALSE;
	}
      }
      if (MY_cache_dbop(&bed->b->desc, elem, idata)) {
	bed->b->fail = TRUE; 
	bed->b->connected = FALSE;
      }
    }
  }
  if (config.sql_recovery_logfile) {
    int sz;

    if (!bed->lf->fail) {
      if (!bed->lf->open) {
        bed->lf->file = MY_file_open(config.sql_recovery_logfile, idata);
        if (!bed->lf->file) bed->lf->fail = TRUE;
        else bed->lf->open = TRUE;
      }
      if (!bed->lf->fail) {
	sz = TPL_push(logbuf.ptr, elem);
	if ((logbuf.ptr+sz) > logbuf.end) {
	  fwrite(logbuf.base, (logbuf.ptr-logbuf.base), 1, bed->lf->file);
	  logbuf.ptr = logbuf.base;
	}
	else logbuf.ptr += sz;
      }
    }
  }
}

void MY_Unlock(struct BE_descs *bed)
{
  if (!bed->p->fail) mysql_query(&bed->p->desc, unlock_clause);

  if (config.sql_backup_host) {
    if (bed->b->connected && (!bed->b->fail)) mysql_query(&bed->b->desc, unlock_clause);
  }
  if (config.sql_recovery_logfile) {
    if (bed->lf->file) {
      if (logbuf.ptr != logbuf.base) {
        fwrite(logbuf.base, (logbuf.ptr-logbuf.base), 1, bed->lf->file);
	logbuf.ptr = logbuf.base;
      }
      file_unlock(fileno(bed->lf->file));
      fclose(bed->lf->file);
    }
  }
}

FILE *MY_file_open(const char *path, const struct insert_data *idata)
{
  struct stat st, st2;
  struct logfile_header lh;
  struct template_header tth;
  FILE *f;
  int ret;

  file_open:
  f = fopen(path, "a+");
  if (f) {
    if (file_lock(fileno(f))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock of '%s'.\n", path);
      goto close;
    }

    fstat(fileno(f), &st); 
    if (!st.st_size) {
      memset(&lh, 0, sizeof(struct logfile_header));
      strlcpy(lh.sql_db, config.sql_db, DEF_HDR_FIELD_LEN);
      strlcpy(lh.sql_table, config.sql_table, DEF_HDR_FIELD_LEN);
      strlcpy(lh.sql_user, config.sql_user, DEF_HDR_FIELD_LEN);
      if (config.sql_host) strlcpy(lh.sql_host, config.sql_host, DEF_HDR_FIELD_LEN);
      else strlcpy(lh.sql_host, "localhost", DEF_HDR_FIELD_LEN);
      lh.sql_table_version = config.sql_table_version;
      lh.sql_table_version = htons(lh.sql_table_version);
      lh.sql_optimize_clauses = config.sql_optimize_clauses;
      lh.sql_optimize_clauses = htons(lh.sql_optimize_clauses); 
      lh.sql_history = config.sql_history;
      lh.sql_history = htons(lh.sql_history);
      lh.what_to_count = htonl(config.what_to_count);
      lh.magic = htonl(MAGIC);

      fwrite(&lh, sizeof(lh), 1, f);
      fwrite(&th, sizeof(th), 1, f);
      fwrite(te, ntohs(th.num)*sizeof(struct template_entry), 1, f);
    }
    else {
      rewind(f);
      fread(&lh, sizeof(lh), 1, f);
      if (ntohl(lh.magic) != MAGIC) {
	Log(LOG_ALERT, "ALERT: Invalid magic number: '%s'.\n", path);
	goto close;
      }
      fread(&tth, sizeof(tth), 1, f);
      if ((tth.num != th.num) || (tth.sz != th.sz)) {
	Log(LOG_ALERT, "ALERT: Invalid template in: '%s'.\n", path);
	goto close;
      }
      if ((st.st_size+(idata->ten*sizeof(struct pkt_data))) >= MAX_LOGFILE_SIZE) {
	Log(LOG_INFO, "INFO: No more space in '%s'.\n", path);

	/* We reached the maximum logfile length; we test if any previous process
	   has already rotated the logfile. If not, we will rotate it. */
	stat(path, &st2); 
	if (st2.st_size >= st.st_size) {
	  ret = file_archive(path, MAX_LOGFILE_ROTATIONS);
	  if (ret < 0) goto close;
	}
	file_unlock(fileno(f));
	fclose(f);
	goto file_open;
      }
      fseek(f, 0, SEEK_END);
    }
  }

  return f;

  close:
  file_unlock(fileno(f));
  fclose(f);
  return NULL; 
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
  char *args[1];
  int pid;

  memset(args, 0, sizeof(args));

  switch (pid = vfork()) {
  case -1:
    return -1;
  case 0:
    execv(filename, args); 
    exit(0);
  }

  return 0;
}

void MY_sum_host_insert(struct pkt_data *data, struct insert_data *idata)
{
  struct in_addr ip;
#if defined ENABLE_IPV6
  struct in6_addr ip6;
#endif

  if (data->primitives.dst_ip.family == AF_INET) {
    ip.s_addr = data->primitives.dst_ip.address.ipv4.s_addr;
    data->primitives.dst_ip.address.ipv4.s_addr = 0;
    data->primitives.dst_ip.family = 0;
    MY_cache_insert(data, idata);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    MY_cache_insert(data, idata);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    insert_accounting_structure(data);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    insert_accounting_structure(data);
    return;
  }
#endif
}

void MY_sum_port_insert(struct pkt_data *data, struct insert_data *idata)
{
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  MY_cache_insert(data, idata);
  data->primitives.src_port = port;
  MY_cache_insert(data, idata);
}
