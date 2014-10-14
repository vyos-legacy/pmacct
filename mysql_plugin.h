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

/* includes */
#include <mysql/mysql.h>

/* structures */
struct DBdesc {
  MYSQL desc;
  short int connected;
  short int locked;
  short int fail;
};

/* prototypes */
void mysql_plugin(int, struct configuration *, void *);
int MY_cache_dbop(MYSQL *, const struct db_cache *, const int);
void MY_cache_purge(struct db_cache *[], int, const int, int);
void MY_handle_collision(struct db_cache *);
int MY_evaluate_history(int);
int MY_compose_static_queries();
unsigned int MY_cache_modulo(struct pkt_primitives *);
void MY_cache_insert(struct pkt_data *, struct insert_data *);
int MY_cache_flush(struct db_cache *[], int, int);
int MY_evaluate_primitives(int);
void MY_exit_gracefully(int);
void MY_Lock(struct DBdesc *, struct DBdesc *, struct logfile *);
void MY_Query(struct DBdesc *, struct DBdesc *, struct logfile *, const struct db_cache *, int);
void MY_Unlock(struct DBdesc *, struct DBdesc *, struct logfile *);
FILE *MY_file_open(const char *, const char *);
int MY_DB_Connect(struct DBdesc *, char *);
int MY_Exec(char *);

/* global vars */
struct DBdesc p;
struct DBdesc b;

