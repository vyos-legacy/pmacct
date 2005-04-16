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

struct preprocess {
  u_int32_t qnum;
  u_int16_t minp;
  u_int32_t minb;
  u_int8_t recover;
};

#if (!defined __PREPROCESS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void set_preprocess_funcs(char *, struct preprocess *);
EXT int cond_qnum(struct db_cache *[], int *);
EXT int check_minp(struct db_cache *[], int *);
EXT int check_minb(struct db_cache *[], int *);

EXT preprocess_func preprocess_funcs[N_FUNCS];
EXT struct preprocess prep;
#undef EXT
