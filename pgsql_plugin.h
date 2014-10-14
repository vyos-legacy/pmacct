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
#include <libpq-fe.h>

/* structures */
struct DBdesc {
  PGconn *desc;
  char *conn_string;
  short int connected;
  short int fail;
};

/* prototypes */
void pgsql_plugin(int, struct configuration *, void *);
int PG_cache_dbop(PGconn *, const struct db_cache *, const int);
void PG_cache_purge(struct db_cache *[], int, const int, int);
void PG_handle_collision(struct db_cache *);
int PG_evaluate_history(int);
int PG_compose_static_queries();
void PG_compose_conn_string(struct DBdesc *, char *);
unsigned int PG_cache_modulo(struct pkt_primitives *);
void PG_cache_insert(struct pkt_data *, struct insert_data *);
int PG_cache_flush(struct db_cache *[], int, int);
int PG_evaluate_primitives(int);
void PG_exit_gracefully(int);
int PG_Query(struct DBdesc *, struct DBdesc *, struct logfile *, const struct db_cache *, int);
FILE *PG_file_open(const char *, const char *);
void PG_file_close(struct logfile *);
int PG_DB_Connect(struct DBdesc *);
static int PG_affected_rows(PGresult *);
int PG_Exec(char *);

/* global vars */
struct DBdesc p;
struct DBdesc b;
int frontend = TRUE;
