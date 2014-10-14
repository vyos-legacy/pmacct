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
#include "once.h"

#if defined (HAVE_MMAP)
#include <sys/mman.h>
#if !defined (MAP_ANONYMOUS)
#if defined (MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#else
#define MAP_ANONYMOUS 0
#define USE_DEVZERO 1
#endif
#endif
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

#include "pmacct-defines.h"
#include "network.h"
#include "cfg.h"
#include "util.h"
#include "log.h"

/* structures */
struct pcap_device {
  pcap_t *dev_desc;
  int link_type;
  int active;
  struct _devices_struct *data; 
};

struct _protocols_struct {
  char name[PROTO_LEN];
  int number;
};

struct _devices_struct {
  void (*handler)(const struct pcap_pkthdr *, register struct packet_ptrs *);
  int link_type;
};

/* prototypes */
void usage_collector(char *);
void startup_handle_falling_child();
void handle_falling_child();
void ignore_falling_child();
void my_sigint_handler();
void reload();

void eth_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
void fddi_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
void ppp_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
void ieee_802_11_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
void sll_handler(const struct pcap_pkthdr *, register struct packet_ptrs *);
u_char *llc_handler(const struct pcap_pkthdr *, u_int, register u_char *);

void usage_collector(char *);
int ip_handler(register struct packet_ptrs *);
void pcap_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
void compute_once();

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

