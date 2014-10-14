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
#include <mysql/mysql.h>

/* structures */
struct DBdesc {
  MYSQL desc;
  short int type;
  short int connected;
  short int fail;
};

struct BE_descs { /* Backend descriptors */
  struct DBdesc *p;
  struct DBdesc *b;
  struct logfile *lf;
};

/* prototypes */
void mysql_plugin(int, struct configuration *, void *);
int MY_cache_dbop(struct DBdesc *, struct db_cache *, struct insert_data *);
void MY_cache_purge(struct db_cache *[], int, struct insert_data *);
int MY_evaluate_history(int);
int MY_compose_static_queries();
void MY_cache_modulo(struct pkt_primitives *, struct insert_data *);
void MY_cache_insert(struct pkt_data *, struct insert_data *);
int MY_cache_flush(struct db_cache *[], int);
int MY_evaluate_primitives(int);
void MY_exit_gracefully(int);
void MY_Lock(struct DBdesc *);
void MY_Query(struct BE_descs *, struct db_cache *, struct insert_data *);
void MY_Unlock(struct BE_descs *);
FILE *MY_file_open(const char *, const struct insert_data *);
void MY_DB_Connect(struct DBdesc *, char *);
void MY_DB_Close(struct BE_descs *); 
void MY_DB_ok(struct DBdesc *);
void MY_DB_fail(struct DBdesc *);
void MY_DB_errmsg(struct DBdesc *);
void MY_create_dyn_table(struct DBdesc *, struct insert_data *);
int MY_Exec(char *);
void MY_sum_host_insert(struct pkt_data *, struct insert_data *);
void MY_sum_port_insert(struct pkt_data *, struct insert_data *);
#if defined (HAVE_L2)
void MY_sum_mac_insert(struct pkt_data *, struct insert_data *);
#endif

#if defined __PMACCT_PLAYER_C
void print_header();
#endif

/* global vars */
void (*insert_func)(struct pkt_data *, struct insert_data *);
struct template_header th;
struct template_entry *te;
struct largebuf logbuf;
struct largebuf envbuf;
struct DBdesc p;
struct DBdesc b;
struct BE_descs bed;
