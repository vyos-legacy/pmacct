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

#define __PMACCT_PLAYER_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"
#include "mysql_plugin.h"
#include "util.h"

#define WANT_ALL_ELEMENTS	1
#define WANT_SINGLE_ELEMENT	2
#define DEFLEN 255
#define ARGS "dp:f:o:sth"

MYSQL db_desc;
struct logfile_header lh;
int re = 0, we = 0;
int debug = 0;

void usage(char *prog)
{
  printf("%s\n", PMMYPLAY_USAGE_HEADER);
  printf("Usage: %s -f [filename]\n\n", prog);
  printf("other options:\n");
  printf("  -d\tenable debug\n");
  printf("  -f\t[filename]\n\tplay specified file\n");
  printf("  -o\t[element]\n\tplay file starting at specified offset element\n");
  printf("  -s\tplay a single element\n");
  printf("  -t\ttest only; don't write anything to the DB.\n");
  printf("  -p\t[password]\n\tconnect to DB using the specified password\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

int main(int argc, char **argv)
{
  FILE *f;
  unsigned char fbuf[SRVBUFLEN];
  char logfile[DEFLEN];
  char sql_pwd[DEFLEN];
  char default_pwd[] = "arealsmartpwd";
  int have_pwd = 0, have_logfile = 0, n;
  int result, type = 0, position = 0; 
  int do_nothing = 0, first_cycle = TRUE;

  struct db_cache *data;
  int num_primitives;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag = 0, cp;

  /* daemonization stuff */
  char default_sock[] = "/tmp/pmmyplay.sock";

  /* signal handling */
  signal(SIGINT, MY_exit_gracefully);

  memset(sql_data, 0, sizeof(sql_data));
  memset(lock_clause, 0, sizeof(lock_clause));
  memset(unlock_clause, 0, sizeof(unlock_clause));
  memset(update_clause, 0, sizeof(update_clause));
  memset(insert_clause, 0, sizeof(insert_clause));
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));

  pp_size = sizeof(struct db_cache);

  while (!errflag && ((cp = getopt(argc, argv, ARGS)) != -1)) {
    switch (cp) {
    case 'd':
      debug = TRUE;
      break;
    case 'p':
      strlcpy(sql_pwd, optarg, sizeof(sql_pwd));
      have_pwd = TRUE;
      break;
    case 'f':
      strlcpy(logfile, optarg, sizeof(logfile));
      have_logfile = TRUE;
      break;
    case 'o':
      position = atoi(optarg);
      break;
    case 's':
      type = WANT_SINGLE_ELEMENT;
      break;
    case 't':
      do_nothing = TRUE;
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  /* searching for user supplied values */ 
  if (!type) type = WANT_ALL_ELEMENTS;
  if (!have_pwd) memcpy(sql_pwd, default_pwd, sizeof(default_pwd));
  if (!have_logfile) {
    usage(argv[0]);
    printf("\nERROR: missing logfile (-f)\nExiting...\n");
    exit(1);
  }

  f = fopen(logfile, "r");
  if (!f) {
    printf("ERROR: %s does not exists\nExiting...\n", logfile);
    exit(1);
  }

  fread(&lh, sizeof(lh), 1, f);
  if (lh.magic == MAGIC) {
    if (debug) printf("OK: Valid logfile header read.\n");
    printf("sql_db: %s\n", lh.sql_db); 
    printf("sql_table: %s\n", lh.sql_table);
    printf("sql_user: %s\n", lh.sql_user);
    printf("sql_host: %s\n", lh.sql_host);
  }
  else {
    printf("ERROR: Invalid magic number.\nExiting...\n");
    exit(1);
  }
  

  if (!do_nothing) {
    mysql_init(&db_desc); 
    if (mysql_real_connect(&db_desc, lh.sql_host, lh.sql_user, sql_pwd, lh.sql_db, 0, NULL, 0) == NULL) {
      printf("%s\n", mysql_error(&db_desc));
      exit(1);
    }
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* composing the proper (filled with primitives used during
     the current execution) SQL strings */
  num_primitives = MY_compose_static_queries();

  /* handling offset */ 
  if (position) n = fseek(f, (sizeof(struct db_cache)*position), SEEK_CUR);

  /* handling single or iterative request */
  if (type == WANT_ALL_ELEMENTS) {
    while(!feof(f)) {
      memset(fbuf, 0, sizeof(struct db_cache));
      n = fread(fbuf, sizeof(struct db_cache), 1, f); 
      if (n) {
        re++;
        data = (struct db_cache *) fbuf;

	if (!do_nothing) {
          mysql_query(&db_desc, lock_clause);
          result = MY_cache_dbop(&db_desc, data, num_primitives);
          mysql_query(&db_desc, unlock_clause);
	}

        if (!result) we++;
        if (re != we) printf("WARN: unable to write element %d.\n", re);
      }
    }
  }

  if (type == WANT_SINGLE_ELEMENT) {
    memset(fbuf, 0, sizeof(struct db_cache));
    n = fread(fbuf, sizeof(struct db_cache), 1, f);
    if (n) {
      data = (struct db_cache *) fbuf;

      if (!do_nothing) {
        mysql_query(&db_desc, lock_clause);
        result = MY_cache_dbop(&db_desc, data, num_primitives);
        mysql_query(&db_desc, unlock_clause);
      }

      if (!result) {
        re = TRUE;
        we = TRUE;
      }
      else printf("WARN: unable to write element.\n");
    }
  }

  if (!do_nothing) printf("\nOK: written [%d/%d] elements.\n", we, re);
  else printf("OK: read [%d] elements.\n", re);
  mysql_close(&db_desc);
  fclose(f);

  return 0;
}

int MY_cache_dbop(MYSQL *db_desc, const struct db_cache *cache_elem, const int num_primitives)
{
  char *ptr_values, *ptr_where;
  int num=0, ret=0;

  ptr_where = where_clause;
  ptr_values = values_clause; 
  while (num < num_primitives) {
    (*where[num].handler)(cache_elem, num, &ptr_values, &ptr_where);
    num++;
  }
  
  /* constructing sql query */
  snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter);
  strncat(sql_data, where_clause, SPACELEFT(sql_data));
  ret = mysql_query(db_desc, sql_data);
  if (ret) return ret; 

  if (mysql_affected_rows(db_desc) == 0) {
    /* UPDATE failed, trying with an INSERT query */ 
    strncpy(sql_data, insert_clause, sizeof(sql_data));
    snprintf(ptr_values, SPACELEFT(values_clause), ", %d, %d)", cache_elem->packet_counter, cache_elem->bytes_counter);
    strncat(sql_data, values_clause, SPACELEFT(sql_data));
    ret = mysql_query(db_desc, sql_data);
    if (ret) return ret;
  }

  if (debug) {
    printf("**********\n");
    printf("%s\n", sql_data);
  }

  return ret;
}

int MY_evaluate_history(int primitive)
{
  if (lh.sql_history) {
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
  short int assume_custom_table = FALSE;

  if (lh.sql_optimize_clauses) {
    what_to_count = lh.what_to_count;
    assume_custom_table = TRUE;
  }
  else {
    /* we are requested to avoid optimization;
       then we'll construct an all-true "what
       to count" bitmap */ 
    what_to_count |= COUNT_SRC_HOST|COUNT_DST_HOST;
    what_to_count |= COUNT_SRC_MAC|COUNT_DST_MAC;
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

    if ((lh.sql_table_version < 2) && !assume_custom_table) {
      if (lh.what_to_count & COUNT_VLAN) {
        printf("ERROR: The use of VLAN accounting requires SQL table v2. Exiting.\n");
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
    strncat(values[primitive].string, "\'%d\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "src_port=\'%d\'", SPACELEFT(where[primitive].string));
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
    strncat(values[primitive].string, "\'%d\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "dst_port=\'%d\'", SPACELEFT(where[primitive].string));
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
                                                                                            
    if ((lh.sql_table_version < 2) && !assume_custom_table) {
      if (lh.what_to_count & COUNT_ID) {
        printf("ERROR: The use of IDs requires SQL table version 2. Exiting.\n");
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

  return primitive;
}

int MY_compose_static_queries()
{
  int primitives=0;

  /* "INSERT INTO ... VALUES ... " and "... WHERE ..." stuff */
  strncpy(where[primitives].string, " WHERE ", sizeof(where[primitives].string));
  snprintf(insert_clause, sizeof(insert_clause), "INSERT INTO %s (", lh.sql_table);
  strncpy(values[primitives].string, " VALUES (", sizeof(values[primitives].string));
  primitives = MY_evaluate_history(primitives);
  primitives = MY_evaluate_primitives(primitives);
  strncat(insert_clause, ", packets, bytes)", SPACELEFT(insert_clause));

  /* "LOCK ..." stuff */
  snprintf(lock_clause, sizeof(lock_clause), "LOCK TABLES %s WRITE", lh.sql_table);
  strncpy(unlock_clause, "UNLOCK TABLES", sizeof(unlock_clause));

  /* "UPDATE ... SET ..." stuff */
  snprintf(update_clause, sizeof(update_clause), "UPDATE %s ", lh.sql_table);
  strncat(update_clause, "SET packets=packets+%d, bytes=bytes+%d", SPACELEFT(update_clause));
  if (lh.sql_history) strncat(update_clause, ", stamp_updated=now()", SPACELEFT(update_clause));

  return primitives;
}

void MY_exit_gracefully(int signum)
{
  printf("\nOK: written [%d/%d] elements.\n", we, re);
  exit(0);
}
