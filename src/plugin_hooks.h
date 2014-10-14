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

#define DEFAULT_CHBUFLEN 4096
#define DEFAULT_PIPE_SIZE 65535
#define WARNING_PIPE_SIZE 16384000 /* 16 Mb */
#define MAX_FAILS 5 
#if defined (HAVE_MMAP)
#define MAX_SEQNUM 65536 
#define MAX_RG_COUNT_ERR 3
#endif

struct channels_list_entry;
typedef void (*pkt_handler) (struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);

struct ring {
  u_int32_t seq;
  char *base;
  char *ptr;
  char *end;
};

struct ch_buf_hdr {
#if defined (HAVE_MMAP)
  u_int32_t seq;
#endif
  int num;
};

struct ch_status {
  u_int8_t wakeup;	/* plugin is polling */ 
};

struct sampling {
  u_int32_t rate;
  u_int32_t counter; 
};

struct channels_list_entry {
  u_int32_t aggregation;
#if !defined (HAVE_MMAP)
  char *buf;		/* ptr to buffer base address */
  char *bufptr;		/* ptr to buffer current address */
  char *bufend;		/* ptr to buffer end address */
#else
  u_int32_t buf;	/* buffer base */
  u_int32_t bufptr;	/* buffer current */
  u_int32_t bufend;	/* buffer end; max 4Gb */
  struct ring rg;	
  struct ch_buf_hdr hdr;
  struct ch_status *status;
  u_int8_t request;			/* does the plugin support on-request wakeup ? */
#endif
  int bufsize;		
  int same_aggregate;
  pkt_handler phandler[N_PRIMITIVES];
  struct bpf_program *filter;
  int pipe;
  u_int16_t id;				/* used to tag packets passing through the channel (post tag) */
  struct pretag_filter tag_filter; 	/* used it to filter pre-tagged packets basing on their id */
  struct sampling s;
};

#if (defined __PLUGIN_HOOKS_C)
extern struct channels_list_entry channels_list[MAX_N_PLUGINS];
#endif

/* Function prototypes */
#if (!defined __PLUGIN_HOOKS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_plugins(struct plugin_requests *);
EXT void exec_plugins(struct packet_ptrs *pptrs);
EXT struct channels_list_entry *insert_pipe_channel(struct configuration *, int); 
EXT void delete_pipe_channel(int);
EXT void sort_pipe_channels();
EXT void init_pipe_channels();
EXT int evaluate_sampling(struct sampling *);
EXT int evaluate_tags(struct pretag_filter *, u_int16_t);
EXT void recollect_pipe_memory(struct channels_list_entry *);
EXT void init_random_seed();
EXT void fill_pipe_buffer();
#undef EXT

#if (defined __PLUGIN_HOOKS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void imt_plugin(int, struct configuration *, void *);
EXT void print_plugin(int, struct configuration *, void *);

#ifdef WITH_MYSQL
EXT void mysql_plugin(int, struct configuration *, void *);
#endif 

#ifdef WITH_PGSQL
EXT void pgsql_plugin(int, struct configuration *, void *);
#endif

#ifdef WITH_SQLITE3
EXT void sqlite3_plugin(int, struct configuration *, void *);
#endif

EXT char *extract_token(char **, int);
#undef EXT
