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

/* defines */
#define ADD 0
#define SUB 1

/* prototypes */
#if (!defined __UTIL_C)
#define EXT extern
#else
#define EXT
#endif
EXT void setnonblocking(int);
EXT void setblocking(int);
EXT int daemonize();
EXT char *copy_argv(register char **);
EXT char *extract_token(char **, int);
EXT char *extract_plugin_name(char **);
EXT void trim_spaces(char *);
EXT void trim_all_spaces(char *);
EXT void strip_quotes(char *);
EXT int isblankline(char *);
EXT int iscomment(char *);
EXT int check_not_valid_char(char *, char *, int);
EXT time_t roundoff_time(time_t, char *);
EXT time_t calc_monthly_timeslot(time_t, int, int);
EXT void write_pid_file(char *);
EXT int sanitize_buf_net(char *, char *, int);
EXT int sanitize_buf(char *);
EXT void mark_columns(char *);
EXT int Setsocksize(int, int, int, void *, int);
EXT void *map_shared(void *, size_t, int, int, int, off_t);
EXT void lower_string(char *);
EXT void evaluate_sums(u_int32_t *, char *, char *);
EXT int file_archive(const char *, int);
EXT void stop_all_childs();
EXT int file_lock(int);
EXT int file_unlock(int);
EXT void strftime_same(char *, int, char *, const time_t *);
EXT int read_SQLquery_from_file(char *, char *, int);

EXT unsigned int str_to_addr(const char *, struct host_addr *);
#undef EXT
