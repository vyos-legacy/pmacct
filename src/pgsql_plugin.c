/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2006 by Paolo Lucente
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

#define __PGSQL_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "pgsql_plugin.h"
#include "util.h"
#include "sql_common_m.c"

/* Functions */
void pgsql_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  struct pollfd pfd;
  struct insert_data idata;
  struct timezone tz;
  time_t refresh_deadline;
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
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "PostgreSQL Plugin", config.name);
  memset(&idata, 0, sizeof(idata));
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);

  sql_set_signals();
  sql_init_default_values();
  PG_init_default_values(&idata);
  PG_set_callbacks(&sqlfunc_cbr);
  sql_set_insert_func();

  /* some LOCAL initialization AFTER setting some default values */
  reload_map = FALSE;
  timeout = config.sql_refresh_time*1000; /* dirty */
  now = time(NULL);
  refresh_deadline = now;

  sql_init_maps(&nt, &nc, &pt);
  sql_init_global_buffers();
  sql_init_pipe(&pfd, pipe_fd);
  sql_init_historical_acct(now, &idata);
  sql_init_triggers(now, &idata);
  sql_init_refresh_deadline(&refresh_deadline);

  /* building up static SQL clauses */
  idata.num_primitives = PG_compose_static_queries();
  glob_num_primitives = idata.num_primitives; 

  /* handling logfile template stuff */
  te = sql_init_logfile_template(&th);
  INIT_BUF(logbuf);

  /* handling purge preprocessor */
  set_preprocess_funcs(config.sql_preprocess, &prep);

  /* setting up environment variables */
  SQL_SetENV();

  sql_link_backend_descriptors(&bed, &p, &b);

  /* plugin main loop */
  for(;;) {
    poll_again:
#if defined (HAVE_MMAP)
    status->wakeup = TRUE;
#endif
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    idata.now = time(NULL);
    now = idata.now;

    switch (ret) {
    case 0: /* poll(): timeout */
      switch (fork()) {
      case 0: /* Child */
	/* we have to ignore signals to avoid loops:
	   because we are already forked */
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	pm_setproctitle("%s [%s]", "PostgreSQL Plugin -- DB Writer", config.name);

	if (qq_ptr) {
	  (*sqlfunc_cbr.connect)(&p, NULL);
          (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, &idata); 
	  (*sqlfunc_cbr.close)(&bed);
	}

	if (config.sql_trigger_exec) {
	  if (idata.now > idata.triggertime) sql_trigger_exec(config.sql_trigger_exec);
	}

        exit(0);
      default: /* Parent */
        if (qq_ptr) qq_ptr = sql_cache_flush(queries_queue, qq_ptr);
	gettimeofday(&idata.flushtime, &tz);
	refresh_deadline += config.sql_refresh_time; 
	if (idata.now > idata.triggertime) {
	  idata.triggertime  += idata.t_timeslot;
	  if (config.sql_trigger_time == COUNT_MONTHLY)
	    idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	}
	idata.new_basetime = FALSE;
	glob_new_basetime = FALSE;
	if (reload_map) {
	  load_networks(config.networks_file, &nt, &nc);
	  load_ports(config.ports_file, &pt);
	  reload_map = FALSE;
	}
        break;
      }
      break;
    default: /* poll(): received data */
#if !defined (HAVE_MMAP)
      if ((ret = read(pipe_fd, pipebuf, config.buffer_size)) == 0) 
        exit_plugin(1); /* we exit silently; something happened at the write end */

      if (ret < 0) goto poll_again;
#else
      read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
        idata.now = time(NULL);
	now = idata.now;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
        if (!pollagain) {
          pollagain = TRUE;
          goto poll_again;
        }
        else {
          rg_err_count++;
          if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
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
	  pm_setproctitle("%s [%s]", "PostgreSQL Plugin -- DB Writer", config.name);

	  if (qq_ptr) {
            (*sqlfunc_cbr.connect)(&p, NULL); 
            (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, &idata);
	    (*sqlfunc_cbr.close)(&bed);
	  }

	  if (config.sql_trigger_exec) {
            if (idata.now > idata.triggertime) sql_trigger_exec(config.sql_trigger_exec);
          }

          exit(0);
        default: /* Parent */
          if (qq_ptr) qq_ptr = sql_cache_flush(queries_queue, qq_ptr);
	  gettimeofday(&idata.flushtime, &tz);
	  refresh_deadline += config.sql_refresh_time; 
	  if (idata.now > idata.triggertime) {
            idata.triggertime  += idata.t_timeslot;
            if (config.sql_trigger_time == COUNT_MONTHLY)
              idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
          }
	  idata.new_basetime = FALSE;
	  glob_new_basetime = FALSE;
	  if (reload_map) {
	    load_networks(config.networks_file, &nt, &nc);
	    load_ports(config.ports_file, &pt);
	    reload_map = FALSE;
	  }
          break;
        }
      } 
      else {
        if (config.sql_trigger_exec) {
          if (idata.now > idata.triggertime) {
            sql_trigger_exec(config.sql_trigger_exec);
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
	glob_basetime = idata.basetime;
	idata.new_basetime = TRUE;
	glob_new_basetime = TRUE;
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

int PG_cache_dbop(struct DBdesc *db, struct db_cache *cache_elem, struct insert_data *idata)
{
  PGresult *ret;
  char *ptr_values, *ptr_where;
  int num=0, have_flows=0;

  if (config.what_to_count & COUNT_FLOWS) have_flows = TRUE;

  /* constructing SQL query */
  ptr_where = where_clause;
  ptr_values = values_clause; 
  memset(where_clause, 0, sizeof(where_clause));
  memset(values_clause, 0, sizeof(values_clause));
  while (num < idata->num_primitives) {
    (*where[num].handler)(cache_elem, idata, num, &ptr_values, &ptr_where);
    num++;
  }

  /* sending UPDATE query */
  if (!config.sql_dont_try_update) {
    /* searching for pending accumulators: this means we know of unclassified counters has been
       kicked to the DB previously; we now try to remove such data by issuing a negative UPDATE
       query. If we are successfull, we add the counters to the new class. Otherwise we discard
       them. */
    if (config.what_to_count & COUNT_CLASS && cache_elem->ba) {
      char local_where_clause[LONGSRVBUFLEN], local_values_clause[LONGSRVBUFLEN];
      char *local_ptr_where = local_where_clause, *local_ptr_values = local_values_clause;
      pm_class_t tmp = cache_elem->primitives.class;

      cache_elem->primitives.class = 0; num = 0;
      memset(local_where_clause, 0, sizeof(local_where_clause));
      memset(local_values_clause, 0, sizeof(local_values_clause));
      while (num < idata->num_primitives) {
        (*where[num].handler)(cache_elem, idata, num, &local_ptr_values, &local_ptr_where);
        num++;
      }
      if (have_flows) snprintf(sql_data, sizeof(sql_data), update_negative_clause, cache_elem->pa, cache_elem->ba, cache_elem->fa);
      else snprintf(sql_data, sizeof(sql_data), update_negative_clause, cache_elem->pa, cache_elem->ba);
      strncat(sql_data, local_where_clause, SPACELEFT(sql_data));
      cache_elem->primitives.class = tmp;

      ret = PQexec(db->desc, sql_data);
      if (PQresultStatus(ret) != PGRES_COMMAND_OK) {
	db->errmsg = PQresultErrorMessage(ret);
	PQclear(ret);
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, sql_data);
	if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): %s\n\n", config.name, config.type, db->errmsg);
	return TRUE;
      }
      PQclear(ret);

      if (PG_affected_rows(ret)) {
        cache_elem->bytes_counter += cache_elem->ba;
        cache_elem->packet_counter += cache_elem->pa;
        cache_elem->flows_counter += cache_elem->fa;

        Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, sql_data);
        // idata->uqn++; /* XXX: negative UPDATE queries number ? */
      }
    }

    /* XXX: optimize time() usage */
    if (have_flows) snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter, now);
    else snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter, now);
    strncat(sql_data, where_clause, SPACELEFT(sql_data));

    ret = PQexec(db->desc, sql_data);
    if (PQresultStatus(ret) != PGRES_COMMAND_OK) {
      db->errmsg = PQresultErrorMessage(ret);
      PQclear(ret);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, sql_data);
      if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): %s\n\n", config.name, config.type, db->errmsg);
      return TRUE;
    }
    PQclear(ret);
  }

  if (config.sql_dont_try_update || (!PG_affected_rows(ret))) {
    /* UPDATE failed, trying with an INSERT query */ 
    strncpy(sql_data, insert_clause, sizeof(sql_data));
#if defined HAVE_64BIT_COUNTERS
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#else
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#endif
    strncat(sql_data, values_clause, SPACELEFT(sql_data));

    ret = PQexec(db->desc, sql_data);
    if (PQresultStatus(ret) != PGRES_COMMAND_OK) {
      db->errmsg = PQresultErrorMessage(ret);
      PQclear(ret);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, sql_data);
      if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): %s\n\n", config.name, config.type, db->errmsg);

      return TRUE;
    }
    PQclear(ret);
    idata->iqn++;
  }
  else idata->uqn++;
  idata->een++;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, sql_data);

  return FALSE;
}

void PG_cache_purge(struct db_cache *queue[], int index, struct insert_data *idata)
{
  PGresult *ret;
  struct logfile lf;
  time_t start;
  int j, r, reprocess = 0, stop;

  memset(&lf, 0, sizeof(struct logfile));
  bed.lf = &lf;

  for (j = 0, stop = 0; (!stop) && preprocess_funcs[j]; j++) 
    stop = preprocess_funcs[j](queue, &index);
  if (config.what_to_count & COUNT_CLASS)
    sql_invalidate_shadow_entries(queue, &index);
  idata->ten = index;

  if (config.debug) {
    Log(LOG_DEBUG, "( %s/%s ) *** Purging cache - START ***\n", config.name, config.type);
    start = time(NULL);
  }

  /* We check for variable substitution in SQL table */
  if (idata->dyn_table) {
    char tmpbuf[LONGLONGSRVBUFLEN];

    strftime_same(insert_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(update_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(update_negative_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(lock_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(delete_shadows_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);

    if (config.sql_table_schema && idata->new_basetime) sql_create_table(bed.p, idata); 
  }
  strncat(update_clause, set_clause, SPACELEFT(update_clause));
  strncat(update_negative_clause, set_negative_clause, SPACELEFT(update_negative_clause));

  /* beginning DB transaction */
  (*sqlfunc_cbr.lock)(bed.p);

  /* for each element of the queue to be processed we execute sql_query(); the function
     returns a non-zero value if DB has failed; then, first failed element is saved to
     allow reprocessing of previous elements if a failover method is in use; elements
     need to be reprocessed because at the time of DB failure they were not yet committed */

  for (j = 0; j < index; j++) {
    if (queue[j]->valid) r = sql_query(&bed, queue[j], idata);
    else r = FALSE; /* not valid elements are marked as not to be reprocessed */ 
    if (r && !reprocess) {
      idata->uqn = 0;
      idata->iqn = 0;
      reprocess = j+1; /* avoding reprocess to be 0 when element j = 0 fails */
    }
  }

  if (config.what_to_count & COUNT_CLASS && !config.sql_dont_try_update)
    (*sqlfunc_cbr.delete_shadows)(&bed);

  /* Finalizing DB transaction */
  if (!p.fail) {
    ret = PQexec(p.desc, "COMMIT");
    if (PQresultStatus(ret) != PGRES_COMMAND_OK) {
      if (!reprocess) {
	sql_db_fail(&p);
        idata->uqn = 0;
        idata->iqn = 0;
        reprocess = j+1;
      }
    }
    PQclear(ret);
  }

  if (p.fail) {
    reprocess--;
    if (reprocess) {
      for (j = 0; j <= reprocess; j++) {
	/* we avoid not valid elements (valid == 0) and already recovered 
	   elements (valid == -1) to be reprocessed */  
        if (queue[j]->valid > 0) sql_query(&bed, queue[j], idata);
      }
    }
  }

  if (b.connected) {
    ret = PQexec(b.desc, "COMMIT");
    if (PQresultStatus(ret) != PGRES_COMMAND_OK) sql_db_fail(&b);
    PQclear(ret);
  }

  /* rewinding stuff */
  if (lf.file) PG_file_close(&lf);
  if (lf.fail || b.fail) Log(LOG_ALERT, "ALERT ( %s/%s ): recovery for PgSQL operation failed.\n", config.name, config.type);

  if (config.debug) {
    idata->elap_time = time(NULL)-start;
    Log(LOG_DEBUG, "( %s/%s ) *** Purging cache - END (QN: %u, ET: %u) ***\n", config.name, config.type, index, idata->elap_time);
  }

  if (config.sql_trigger_exec) {
    if (!config.debug) idata->elap_time = time(NULL)-start;
    SQL_SetENV_child(idata);
  }
}

int PG_evaluate_history(int primitive)
{
  if (config.sql_history) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(where[primitive].string, "ABSTIME(%u)::Timestamp::Timestamp without time zone = ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "stamp_inserted", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "stamp_updated, stamp_inserted", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "ABSTIME(%u)::Timestamp, ABSTIME(%u)::Timestamp", SPACELEFT(values[primitive].string));

    where[primitive].type = values[primitive].type = TIMESTAMP;
    values[primitive].handler = where[primitive].handler = count_timestamp_handler;

    primitive++;
  }

  return primitive;
}

int PG_compose_static_queries()
{
  int primitives=0, have_flows=0;

  if (config.what_to_count & COUNT_FLOWS || (config.sql_table_version >= 4 && !config.sql_optimize_clauses)) {
    config.what_to_count |= COUNT_FLOWS;
    have_flows = TRUE;

    if (config.sql_table_version < 4 && !config.sql_optimize_clauses) {
      Log(LOG_ERR, "ERROR ( %s/%s ): The accounting of flows requires SQL table v4. Exiting.\n", config.name, config.type);
      exit_plugin(1);
    }
  }

  /* "INSERT INTO ... VALUES ... " and "... WHERE ..." stuff */
  strncpy(where[primitives].string, " WHERE ", sizeof(where[primitives].string));
  snprintf(insert_clause, sizeof(insert_clause), "INSERT INTO %s (", config.sql_table);
  strncpy(values[primitives].string, " VALUES (", sizeof(values[primitives].string));
  primitives = PG_evaluate_history(primitives);
  primitives = sql_evaluate_primitives(primitives);
  strncat(insert_clause, ", packets, bytes", SPACELEFT(insert_clause));
  if (have_flows) strncat(insert_clause, ", flows", SPACELEFT(insert_clause));
  strncat(insert_clause, ")", SPACELEFT(insert_clause));

  /* "LOCK ..." stuff */
  if (config.sql_dont_try_update) snprintf(lock_clause, sizeof(lock_clause), "BEGIN;");
  else snprintf(lock_clause, sizeof(lock_clause), "BEGIN; LOCK %s IN EXCLUSIVE MODE;", config.sql_table);

  /* "UPDATE ... SET ..." stuff */
  snprintf(update_clause, sizeof(update_clause), "UPDATE %s ", config.sql_table);
  snprintf(update_negative_clause, sizeof(update_negative_clause), "UPDATE %s ", config.sql_table);
#if defined HAVE_64BIT_COUNTERS
  strncpy(set_clause, "SET packets=packets+%llu, bytes=bytes+%llu", SPACELEFT(set_clause));
  if (have_flows) strncat(set_clause, ", flows=flows+%llu", SPACELEFT(set_clause));
#else
  strncpy(set_clause, "SET packets=packets+%lu, bytes=bytes+%lu", SPACELEFT(set_clause));
  if (have_flows) strncat(set_clause, ", flows=flows+%lu", SPACELEFT(set_clause));
#endif
  if (config.sql_history) strncat(set_clause, ", stamp_updated=CURRENT_TIMESTAMP(0)", SPACELEFT(set_clause)); 
  strncpy(set_negative_clause, "SET packets=packets-%lu, bytes=bytes-%lu", SPACELEFT(set_negative_clause));
  if (have_flows) strncat(set_negative_clause, ", flows=flows-%lu", SPACELEFT(set_negative_clause));
  if (config.sql_history) strncat(set_negative_clause, ", stamp_updated=CURRENT_TIMESTAMP(0)", SPACELEFT(set_negative_clause));

  /* "DELETE ..." stuff */
  snprintf(delete_shadows_clause, sizeof(delete_shadows_clause), "DELETE FROM %s WHERE packets = 0 AND bytes = 0 AND flows = 0", config.sql_table);

  return primitives;
}

void PG_compose_conn_string(struct DBdesc *db, char *host)
{
  char *string;
  int slen = SRVBUFLEN;
  
  if (!db->conn_string) {
    db->conn_string = (char *) malloc(slen);
    string = db->conn_string;

    snprintf(string, slen, "dbname=%s user=%s password=%s", config.sql_db, config.sql_user, config.sql_passwd);
    slen -= strlen(string);
    string += strlen(string);

    if (host) snprintf(string, slen, " host=%s", host);
  }
}

void PG_delete_shadows(struct BE_descs *bed)
{
  PGresult *PGret;
  struct DBdesc *db = NULL;

  if (bed->p->connected) db = bed->p;
  else if (bed->b->connected) db = bed->b;

  if (!db->fail) {
    PGret = PQexec(db->desc, delete_shadows_clause);
    if (PQresultStatus(PGret) != PGRES_COMMAND_OK) {
      db->errmsg = PQresultErrorMessage(PGret);
      sql_db_errmsg(db);
      sql_db_fail(db);
    }
    PQclear(PGret);
  }
}

void PG_Lock(struct DBdesc *db)
{
  PGresult *PGret;

  if (!db->fail) {
    PGret = PQexec(db->desc, lock_clause);
    if (PQresultStatus(PGret) != PGRES_COMMAND_OK) {
      db->errmsg = PQresultErrorMessage(PGret);
      sql_db_errmsg(db);
      sql_db_fail(db);
    }
    PQclear(PGret);
  }
}

void PG_file_close(struct logfile *lf)
{
  if (logbuf.ptr != logbuf.base) {
    fwrite(logbuf.base, (logbuf.ptr-logbuf.base), 1, lf->file);
    logbuf.ptr = logbuf.base;
  }
  file_unlock(fileno(lf->file));
  fclose(lf->file);
}

void PG_DB_Connect(struct DBdesc *db, char *host)
{
  db->desc = PQconnectdb(db->conn_string);
  if (PQstatus(db->desc) == CONNECTION_BAD) {
    char errmsg[64+SRVBUFLEN];

    sql_db_fail(db);
    strcpy(errmsg, "Failed connecting to ");
    strcat(errmsg, db->conn_string);
    db->errmsg = errmsg;
    sql_db_errmsg(db);
  }
  else sql_db_ok(db);
}

void PG_DB_Close(struct BE_descs *bed)
{
  if (bed->p->connected) PQfinish(bed->p->desc);
  if (bed->b->connected) PQfinish(bed->b->desc);
}

void PG_create_dyn_table(struct DBdesc *db, char *buf)
{
  char *err_string;
  PGresult *PGret;

  PGret = PQexec(db->desc, buf);
  if (PQresultStatus(PGret) != PGRES_COMMAND_OK) {
    err_string = PQresultErrorMessage(PGret);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, buf);
    Log(LOG_ERR, "ERROR ( %s/%s ): %s\n\n", config.name, config.type, err_string);
  }
  PQclear(PGret);
}

static int PG_affected_rows(PGresult *result)
{
  return atoi(PQcmdTuples(result));
}

void PG_create_backend(struct DBdesc *db)
{
  if (db->type == BE_TYPE_BACKUP) {
    if (!config.sql_backup_host) return;
  } 

  PG_compose_conn_string(db, config.sql_host);
}

void PG_set_callbacks(struct sqlfunc_cb_registry *cbr)
{
  memset(cbr, 0, sizeof(struct sqlfunc_cb_registry));

  cbr->connect = PG_DB_Connect;
  cbr->close = PG_DB_Close;
  cbr->lock = PG_Lock;
  /* cbr->unlock */ 
  cbr->op = PG_cache_dbop;
  cbr->create_table = PG_create_dyn_table;
  cbr->purge = PG_cache_purge;
  cbr->create_backend = PG_create_backend;
  cbr->delete_shadows = PG_delete_shadows;
}

void PG_init_default_values(struct insert_data *idata)
{
  /* Linking database parameters */
  if (!config.sql_data) config.sql_data = typed_str;
  if (!config.sql_user) config.sql_user = pgsql_user;
  if (!config.sql_db) config.sql_db = pgsql_db;
  if (!config.sql_passwd) config.sql_passwd = pgsql_pwd;
  if (!config.sql_table) {
    /* checking 'typed' table constraints */
    if (!strcmp(config.sql_data, "typed")) {
      if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS|COUNT_DST_AS) && config.what_to_count &
	(COUNT_SRC_HOST|COUNT_SUM_HOST|COUNT_DST_HOST|COUNT_SRC_NET|COUNT_SUM_NET|COUNT_DST_NET) &&
	config.sql_table_version < 6) {
	Log(LOG_ERR, "ERROR ( %s/%s ): 'typed' PostgreSQL table in use: unable to mix HOST/NET and AS aggregations.\n", config.name, config.type);
	exit_plugin(1);
      }
      typed = TRUE;
    }
    else if (!strcmp(config.sql_data, "unified")) typed = FALSE;
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): Ignoring unknown 'sql_data' value '%s'.\n", config.name, config.type, config.sql_data);
      exit_plugin(1);
    }

    if (typed) {
      if (config.sql_table_version == 6) config.sql_table = pgsql_table_v6; 
      else if (config.sql_table_version == 5) {
        if (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) config.sql_table = pgsql_table_as_v5;
        else config.sql_table = pgsql_table_v5;
      }
      else if (config.sql_table_version == 4) {
	if (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) config.sql_table = pgsql_table_as_v4;
	else config.sql_table = pgsql_table_v4;
      }
      else if (config.sql_table_version == 3) {
	if (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) config.sql_table = pgsql_table_as_v3;
	else config.sql_table = pgsql_table_v3;
      }
      else if (config.sql_table_version == 2) {
	if (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) config.sql_table = pgsql_table_as_v2;
	else config.sql_table = pgsql_table_v2;
      }
      else {
	if (config.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) config.sql_table = pgsql_table_as;
	else config.sql_table = pgsql_table;
      }
    }
    else {
      if (config.sql_table_version == 6) {
	Log(LOG_WARNING, "WARN ( %s/%s ): Unified data are no longer supported. Switching to typed data.\n", config.name, config.type);
	config.sql_table = pgsql_table_v6;
      }
      else if (config.sql_table_version == 5) config.sql_table = pgsql_table_uni_v5;
      else if (config.sql_table_version == 4) config.sql_table = pgsql_table_uni_v4;
      else if (config.sql_table_version == 3) config.sql_table = pgsql_table_uni_v3;
      else if (config.sql_table_version == 2) config.sql_table = pgsql_table_uni_v2;
      else config.sql_table = pgsql_table_uni;
    }
  }
  if (strchr(config.sql_table, '%')) idata->dyn_table = TRUE;
  glob_dyn_table = idata->dyn_table;

  if (config.sql_backup_host || config.sql_recovery_logfile) idata->recover = TRUE;
}
