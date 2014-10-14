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

/* prototypes */
void setnonblocking(int);
void setblocking(int);
int daemonize();
char *copy_argv(register char **);
char *extract_token(char **, int);
char *extract_plugin_name(char **);
void trim_spaces(char *);
void trim_all_spaces(char *);
int isblankline(char *);
int iscomment(char *);
int check_not_valid_char(char *, int);
void debug_packet(struct pkt_data *);
time_t roundoff_time(time_t);
void write_pid_file(char *);
int sanitize_buf_net(char *, int);
int sanitize_buf(char *);
void mark_columns(char *);
int Setsocksize(int, int, int, void *, int);
void *map_shared(void *, size_t, int, int, int, off_t);
