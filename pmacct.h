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
#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif
#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h> 
#endif

#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <signal.h>
#include <syslog.h>

#include <sys/mman.h>
#if !defined (MAP_ANONYMOUS)
#if defined (MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0
#define USE_DEVZERO 1
#endif
#endif

#if !defined INET_ADDRSTRLEN 
#define INET_ADDRSTRLEN 16
#endif
#if !defined INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifdef SOLARIS
#define htons(x) (x)
#define htonl(x) (x)
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#endif

#ifndef LOCK_UN
#define LOCK_UN 8
#endif

#ifndef LOCK_EX
#define LOCK_EX 2
#endif

#ifdef NOINLINE
#define Inline
#else
#define Inline static inline
#endif

/* Let work the unaligned copy macros the hard way: byte-per byte copy via
   u_char pointers. We discard the packed attribute way because it fits just
   to GNU compiler */
#if !defined NEED_ALIGN
#define Assign8(a, b) a = b
#else
#define Assign8(a, b)		\
{             			\
  u_char *ptr = (u_char *)&a;	\
  *ptr = b;			\
}
#endif

#if !defined NEED_ALIGN
#define Assign16(a, b) a = b
#else
#define Assign16(a, b)		\
{      				\
  u_int16_t c = b;		\
  u_char *dst = (u_char *)&a;	\
  u_char *src = (u_char *)&c;	\
  *(dst + 0) = *(src + 0);	\
  *(dst + 1) = *(src + 1);	\
}
#endif

#if !defined NEED_ALIGN
#define Assign32(a, b) a = b
#else
#define Assign32(a, b)		\
{             			\
  u_int32_t c = b;		\
  u_char *dst = (u_char *)&a;	\
  u_char *src = (u_char *)&c;	\
  *(dst + 0) = *(src + 0);	\
  *(dst + 1) = *(src + 1);	\
  *(dst + 2) = *(src + 2);	\
  *(dst + 3) = *(src + 3);	\
}
#endif

#include "pmacct-defines.h"
#include "network.h"
#include "pretag.h"
#include "cfg.h"
#include "util.h"
#include "log.h"
#include "once.h"

/* structures */
struct pcap_device {
  pcap_t *dev_desc;
  int link_type;
  int active;
  struct _devices_struct *data; 
};

struct pcap_callback_data {
  u_char * idt; 
  struct pcap_device *device;
};

struct _protocols_struct {
  char name[PROTO_LEN];
  int number;
};

struct _devices_struct {
  void (*handler)(const struct pcap_pkthdr *, register struct packet_ptrs *);
  int link_type;
};

struct smallbuf {
  u_char base[SRVBUFLEN];
  u_char *end;
  u_char *ptr;
};	

struct largebuf {
  u_char base[LARGEBUFLEN];
  u_char *end;
  u_char *ptr;
};

#define INIT_BUF(x) \
	memset(x.base, 0, sizeof(x.base)); \
	x.end = x.base+sizeof(x.base); \
	x.ptr = x.base;

struct plugin_requests {
  u_int8_t bpf_filter; /* On-request packet copy for BPF purposes */
};

/* prototypes */
void startup_handle_falling_child();
void handle_falling_child();
void ignore_falling_child();
void my_sigint_handler();
void reload();

#if (!defined __LL_C)
#define EXT extern
#else
#define EXT
#endif
EXT void eth_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void fddi_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void ppp_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void ieee_802_11_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void sll_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT void raw_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
EXT u_char *llc_handler(const struct pcap_pkthdr *, u_int, register u_char *, register struct packet_ptrs *);
#undef EXT

#if (!defined __PMACCTD_C) 
#define EXT extern
#else
#define EXT
#endif
EXT int ip_handler(register struct packet_ptrs *);
EXT int ip6_handler(register struct packet_ptrs *);
EXT void pcap_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
EXT int PM_find_id(struct packet_ptrs *);
EXT void compute_once();
#undef EXT

size_t strlcpy(char *, const char *, size_t);

/* global variables */
pcap_t *glob_pcapt;
struct pcap_stat ps;

#if (!defined __PMACCTD_C) && (!defined __NFACCTD_C)
extern int debug;
extern int have_num_memory_pools; /* global getopt() stuff */
extern struct configuration config; /* global configuration structure */ 
extern struct plugins_list_entry *plugins_list; /* linked list of each plugin configuration */
extern struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
extern pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
#endif

