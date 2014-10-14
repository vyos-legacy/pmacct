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
#define __NFACCTD_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pretag-data.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"

/* variables to be exported away */
int debug;
struct configuration config; /* global configuration */ 
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */ 
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
int have_num_memory_pools; /* global getopt() stuff */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s\n", NFACCTD_USAGE_HEADER);
  printf("Usage: %s [-D|-d] [-L IP address] [-l port] [-c primitive[,...]] [-P plugin[,...]]\n", prog_name);
  printf("       %s [-f config_file]\n", prog_name);
  printf("       %s [-h]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tshow this page\n");
  printf("  -L  \tbind to the specified IP address\n");
  printf("  -l  \tlisten on the specified UDP port\n");
  printf("  -f  \tconfiguration file (see also CONFIG-KEYS)\n");
  printf("  -c  \t[src_mac|dst_mac|vlan|src_host|dst_host|src_net|dst_net|src_port|dst_port|tos|proto|src_as|dst_as, \n\t ,sum_mac,sum_host,sum_net,sum_as,sum_port,tag,flows,none] \n\taggregation primitives and flows (DEFAULT: src_host)\n");
  printf("  -D  \tdaemonize\n"); 
  printf("  -n  \tpath to a file containing network definitions; to be used in conjunction with 'src_net' or 'dst_net'\n");
  printf("  -o  \tpath to a file containing port definitions\n");
  printf("  -P  \t[memory|print|mysql|pgsql] \n\tactivate plugin\n"); 
  printf("  -d  \tenables debug\n");
  printf("  -S  \t[auth|mail|daemon|kern|user|local[0-7]] \n\tsyslog facility\n");
  printf("  -F  \twrite Core Process PID into the specified file\n");
  printf("\nMemory Plugin (-P memory) options:\n");
  printf("  -p  \tsocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tnumber of buckets\n");
  printf("  -m  \tnumber of memory pools\n");
  printf("  -s  \tmemory pool size\n");
  printf("\nPostgreSQL (-P pgsql)/MySQL (-P mysql) plugin options:\n");
  printf("  -r  \trefresh time (in seconds)\n");
  printf("  -v  \t[1|2|3|4] \n\ttable version\n");
  printf("\n");
  printf("Examples:\n");
  printf("  Daemonize the process and write data into a MySQL database\n");
  printf("  nfacctd -c src_host,dst_host -D -P mysql\n\n");
  printf("  Print flows over the screen and refresh data every 30 seconds\n");
  printf("  nfacctd -c src_host,dst_host,proto -P print -r 30\n");
  printf("\n");
  printf("  See EXAMPLES for further hints\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  struct packet_ptrs_vector pptrs;
  char config_file[SRVBUFLEN];
  unsigned char netflow_packet[NETFLOW_MSG_SIZE];
  int logf, sd, rc, yes=1, allowed;
  struct host_addr addr;
  struct hosts_table allow;
  struct id_table idt;
  u_int16_t ret;

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
#else
  struct sockaddr server, client;
#endif
  int clen = sizeof(client), slen;

  /* dummy stuff */
  struct pcap_device device;

  unsigned char dummy_packet[64]; 
  unsigned char dummy_packet_vlan[64]; 
  unsigned char dummy_packet_mpls[128]; 
  unsigned char dummy_packet_vlan_mpls[128]; 
  struct pcap_pkthdr dummy_pkthdr;
  struct pcap_pkthdr dummy_pkthdr_vlan;
  struct pcap_pkthdr dummy_pkthdr_mpls;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls;

#if defined ENABLE_IPV6
  unsigned char dummy_packet6[92]; 
  unsigned char dummy_packet_vlan6[92]; 
  unsigned char dummy_packet_mpls6[128]; 
  unsigned char dummy_packet_vlan_mpls6[128]; 
  struct pcap_pkthdr dummy_pkthdr6;
  struct pcap_pkthdr dummy_pkthdr_vlan6;
  struct pcap_pkthdr dummy_pkthdr_mpls6;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls6;
#endif

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp; 

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  have_num_memory_pools = FALSE;
  errflag = 0;

  memset(&server, 0, sizeof(server));
  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&pptrs, 0, sizeof(pptrs));
  memset(&req, 0, sizeof(req));
  config.acct_type = ACCT_NF;

  rows = 0;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_NFACCTD)) != -1)) {
    cfg[rows] = malloc(SRVBUFLEN);
    switch (cp) {
    case 'L':
      strcpy(cfg[rows], "nfacctd_ip: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'l':
      strcpy(cfg[rows], "nfacctd_port: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'P':
      strcpy(cfg[rows], "plugins: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'D':
      strcpy(cfg[rows], "daemonize: true");
      rows++;
      break;
    case 'd':
      debug = TRUE;
      strcpy(cfg[rows], "debug: true");
      rows++;
      break;
    case 'n':
      strcpy(cfg[rows], "networks_file: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'o':
      strcpy(cfg[rows], "ports_file: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
      break;
    case 'F':
      strcpy(cfg[rows], "pidfile: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'c':
      strcpy(cfg[rows], "aggregate: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'b':
      strcpy(cfg[rows], "imt_buckets: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'm':
      strcpy(cfg[rows], "imt_mem_pools_number: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      have_num_memory_pools = TRUE;
      rows++;
      break;
    case 'p':
      strcpy(cfg[rows], "imt_path: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'r':
      strcpy(cfg[rows], "sql_refresh_time: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      cfg[rows] = malloc(SRVBUFLEN);
      strcpy(cfg[rows], "print_refresh_time: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'v':
      strcpy(cfg[rows], "sql_table_version: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 's':
      strcpy(cfg[rows], "imt_mem_pools_size: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'S':
      strcpy(cfg[rows], "syslog: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    default:
      usage_daemon(argv[0]);
      exit(1);
      break;
    }
  }

  /* post-checks and resolving conflicts */
  if (strlen(config_file)) {
    if (parse_configuration_file(config_file) != SUCCESS) 
      exit(1);
  }
  else {
    if (parse_configuration_file(NULL) != SUCCESS)
      exit(1);
  }
    
  /* XXX: glue; i'm conscious it's a dirty solution from an engineering viewpoint;
     someday later i'll fix this */
  list = plugins_list;
  while(list) {
    if (!strcmp(list->name, "default") && !strcmp(list->type.string, "core")) {
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.acct_type = ACCT_NF;
      break;
    }
    list = list->next;
  }

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print")) printf("WARN: Daemonizing. Hmm, bye bye screen.\n");
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN: debug is enabled; forking in background. Console logging will get lost.\n"); 
    daemonize();
    signal(SIGINT, SIG_IGN);
  }

  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      Log(LOG_WARNING, "WARN ( default/core ): specified syslog facility is not supported; logging to console.\n");
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( default/core ): Start logging ...\n");
  }

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (strcmp(list->type.string, "core")) {  
      evaluate_sums(&list->cfg.what_to_count, list->name, list->type.string);
      if (!list->cfg.what_to_count) {
	Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	list->cfg.what_to_count |= COUNT_SRC_HOST;
      }
      if ((list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) && !list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_KEEP) {
        Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation has been selected but NO networks file has been specified. Exiting...\n\n", list->name, list->type.string);
        exit(1);
      }
      if ((list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET)) && !list->cfg.networks_file && !list->cfg.networks_mask) {
        Log(LOG_ERR, "ERROR ( %s/%s ): NET aggregation has been selected but NO networks file has been specified. Exiting...\n\n", list->name, list->type.string);
        exit(1);
      }
      if (((list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) && (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS))) ||
          ((list->cfg.what_to_count & COUNT_DST_NET) && (list->cfg.what_to_count & COUNT_DST_AS))) {
        Log(LOG_ERR, "ERROR ( %s/%s ): NET/AS are mutually exclusive. Exiting...\n\n", list->name, list->type.string);
        exit(1);
      }
    } 
    list = list->next;
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
  if (!config.nfacctd_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.nfacctd_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.nfacctd_ip);
    ret = str_to_addr(config.nfacctd_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( default/core ): 'nfacctd_ip' value is not valid. Exiting.\n");
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
  }

  /* socket creation */
  sd = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
  if (sd < 0) {
    Log(LOG_ERR, "ERROR ( default/core ): socket() failed.\n");
    exit(1);
  }

  /* bind socket to port */
  rc = Setsocksize(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): Setsocksize() failed for SO_REUSEADDR.\n");

  if (config.pipe_size) {
    rc = Setsocksize(sd, SOL_SOCKET, SO_RCVBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): Setsocksize() failed for 'plugin_pipe_size' = '%d'.\n", config.pipe_size); 
  }

  rc = bind(sd, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( default/core): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.nfacctd_ip, config.nfacctd_port, errno);
    exit(1);
  }

  if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);
  else memset(&allow, 0, sizeof(allow));

  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt, &req);
    pptrs.v4.idtable = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    pptrs.v4.idtable = NULL;
  }
  load_nfv8_handlers();

  /* plugins glue: creation */
  memset(&device, 0, sizeof(struct pcap_device));
  device.dev_desc = pcap_open_dead(1, 128); /* link=1,snaplen=eth_header+my_iphdr+my_tlhdr */
  load_plugins(&device, &req);
  pcap_close(device.dev_desc);
  evaluate_packet_handlers();

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  if (!config.daemon) signal(SIGINT, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* initializing template cache */ 
  memset(&tpl_cache, 0, sizeof(tpl_cache));
  tpl_cache.num = TEMPLATE_CACHE_ENTRIES;

  /* arranging static pointers to dummy packet; to speed up things into the
     main loop we mantain two packet_ptrs structures when IPv6 is enabled:
     we will sync here 'pptrs6' for common tables and pointers */
  memset(dummy_packet, 0, sizeof(dummy_packet));
  pptrs.v4.f_agent = (u_char *) &client;
  pptrs.v4.packet_ptr = dummy_packet;
  pptrs.v4.pkthdr = &dummy_pkthdr;
  Assign16(((struct eth_header *)pptrs.v4.packet_ptr)->ether_type, htons(ETHERTYPE_IP)); /* 0x800 */
  pptrs.v4.mac_ptr = (u_char *)((struct eth_header *)pptrs.v4.packet_ptr)->ether_dhost; 
  pptrs.v4.iph_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN; 
  pptrs.v4.tlh_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN + sizeof(struct my_iphdr); 
  Assign8(((struct my_iphdr *)pptrs.v4.iph_ptr)->ip_vhl, 5);
  pptrs.v4.pkthdr->caplen = 38; /* eth_header + my_iphdr + my_tlhdr */
  pptrs.v4.pkthdr->len = 100; /* fake len */ 
  pptrs.v4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan, 0, sizeof(dummy_packet_vlan));
  pptrs.vlan4.idtable = pptrs.v4.idtable;
  pptrs.vlan4.f_agent = (u_char *) &client;
  pptrs.vlan4.packet_ptr = dummy_packet_vlan;
  pptrs.vlan4.pkthdr = &dummy_pkthdr_vlan;
  Assign16(((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_dhost;
  pptrs.vlan4.vlan_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlan4.vlan_ptr+2), htons(ETHERTYPE_IP));
  pptrs.vlan4.iph_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan4.tlh_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct my_iphdr);
  Assign8(((struct my_iphdr *)pptrs.vlan4.iph_ptr)->ip_vhl, 5);
  pptrs.vlan4.pkthdr->caplen = 42; /* eth_header + vlan + my_iphdr + my_tlhdr */
  pptrs.vlan4.pkthdr->len = 100; /* fake len */
  pptrs.vlan4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_mpls, 0, sizeof(dummy_packet_mpls));
  pptrs.mpls4.idtable = pptrs.v4.idtable;
  pptrs.mpls4.f_agent = (u_char *) &client;
  pptrs.mpls4.packet_ptr = dummy_packet_mpls;
  pptrs.mpls4.pkthdr = &dummy_pkthdr_mpls;
  Assign16(((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_dhost;
  pptrs.mpls4.mpls_ptr = pptrs.mpls4.packet_ptr + ETHER_HDRLEN;
  pptrs.mpls4.pkthdr->caplen = 78; /* eth_header + upto 10 MPLS labels + my_iphdr + my_tlhdr */
  pptrs.mpls4.pkthdr->len = 100; /* fake len */
  pptrs.mpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan_mpls, 0, sizeof(dummy_packet_vlan_mpls));
  pptrs.vlanmpls4.idtable = pptrs.v4.idtable;
  pptrs.vlanmpls4.f_agent = (u_char *) &client;
  pptrs.vlanmpls4.packet_ptr = dummy_packet_vlan_mpls;
  pptrs.vlanmpls4.pkthdr = &dummy_pkthdr_vlan_mpls;
  Assign16(((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_dhost;
  pptrs.vlanmpls4.vlan_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlanmpls4.vlan_ptr+2), htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls4.mpls_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlanmpls4.pkthdr->caplen = 82; /* eth_header + vlan + upto 10 MPLS labels + my_iphdr + my_tlhdr */
  pptrs.vlanmpls4.pkthdr->len = 100; /* fake len */
  pptrs.vlanmpls4.l3_proto = ETHERTYPE_IP;

#if defined ENABLE_IPV6
  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  pptrs.v6.idtable = pptrs.v4.idtable;
  pptrs.v6.f_agent = (u_char *) &client;
  pptrs.v6.packet_ptr = dummy_packet6;
  pptrs.v6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs.v6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs.v6.mac_ptr = (u_char *)((struct eth_header *)pptrs.v6.packet_ptr)->ether_dhost; 
  pptrs.v6.iph_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN;
  pptrs.v6.tlh_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_hlim, htons(64));
  pptrs.v6.pkthdr->caplen = 60; /* eth_header + ip6_hdr + my_tlhdr */
  pptrs.v6.pkthdr->len = 100; /* fake len */
  pptrs.v6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan6, 0, sizeof(dummy_packet_vlan6));
  pptrs.vlan6.idtable = pptrs.v4.idtable;
  pptrs.vlan6.f_agent = (u_char *) &client;
  pptrs.vlan6.packet_ptr = dummy_packet_vlan6;
  pptrs.vlan6.pkthdr = &dummy_pkthdr_vlan6;
  Assign16(((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_dhost;
  pptrs.vlan6.vlan_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlan6.vlan_ptr+2), htons(ETHERTYPE_IPV6));
  pptrs.vlan6.iph_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan6.tlh_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_hlim, htons(64));
  pptrs.vlan6.pkthdr->caplen = 64; /* eth_header + vlan + ip6_hdr + my_tlhdr */
  pptrs.vlan6.pkthdr->len = 100; /* fake len */
  pptrs.vlan6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_mpls6, 0, sizeof(dummy_packet_mpls6));
  pptrs.mpls6.idtable = pptrs.v4.idtable;
  pptrs.mpls6.f_agent = (u_char *) &client;
  pptrs.mpls6.packet_ptr = dummy_packet_mpls6;
  pptrs.mpls6.pkthdr = &dummy_pkthdr_mpls6;
  Assign16(((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_dhost;
  pptrs.mpls6.mpls_ptr = pptrs.mpls6.packet_ptr + ETHER_HDRLEN;
  pptrs.mpls6.pkthdr->caplen = 100; /* eth_header + upto 10 MPLS labels + ip6_hdr + my_tlhdr */
  pptrs.mpls6.pkthdr->len = 128; /* fake len */
  pptrs.mpls6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan_mpls6, 0, sizeof(dummy_packet_vlan_mpls6));
  pptrs.vlanmpls6.idtable = pptrs.v4.idtable;
  pptrs.vlanmpls6.f_agent = (u_char *) &client;
  pptrs.vlanmpls6.packet_ptr = dummy_packet_vlan_mpls6;
  pptrs.vlanmpls6.pkthdr = &dummy_pkthdr_vlan_mpls6;
  Assign16(((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_dhost;
  pptrs.vlanmpls6.vlan_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlanmpls6.vlan_ptr+2), htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls6.mpls_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlanmpls6.pkthdr->caplen = 104; /* eth_header + vlan + upto 10 MPLS labels + ip6_hdr + my_tlhdr */
  pptrs.vlanmpls6.pkthdr->len = 128; /* fake len */
  pptrs.vlanmpls6.l3_proto = ETHERTYPE_IP;
#endif

  Log(LOG_INFO, "INFO ( default/core ): waiting for data on UDP port '%u'\n", config.nfacctd_port);
  allowed = TRUE;

  /* Main loop */
  for(;;) {
    ret = recvfrom(sd, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);

    if (ret < 1) continue; /* we don't have enough data to decode the version */ 

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    /* We will change byte ordering in order to avoid a bunch of ntohs() calls */
    ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);
    
    switch(((struct struct_header_v5 *)netflow_packet)->version) {
    case 1:
      process_v1_packet(netflow_packet, ret, &pptrs.v4, &req);
      break;
    case 5:
      process_v5_packet(netflow_packet, ret, &pptrs.v4, &req); 
      break;
    case 7:
      process_v7_packet(netflow_packet, ret, &pptrs.v4, &req);
      break;
    case 8:
      process_v8_packet(netflow_packet, ret, &pptrs.v4, &req);
      break;
    case 9:
      process_v9_packet(netflow_packet, ret, &pptrs, &req);
      break;
    default:
      notify_malf_packet(LOG_INFO, "INFO: Discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent);
      break;
    }
  }
}

void process_v1_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct plugin_requests *req)
{
  struct struct_header_v1 *hdr_v1 = (struct struct_header_v1 *)pkt;
  struct struct_export_v1 *exp_v1;
  unsigned short int count = ntohs(hdr_v1->count);

  if (len < NfHdrV1Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV1Sz; 
  exp_v1 = (struct struct_export_v1 *)pkt;

  reset_mac(pptrs);

  if ((count <= V1_MAXFLOWS) && ((count*NfDataV1Sz)+NfHdrV1Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v1;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v1->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v1->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v1->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v1->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v1->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v1->dstport);
      }

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v1++;           
      count--;             
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
}

void process_v5_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct plugin_requests *req)
{
  struct struct_header_v5 *hdr_v5 = (struct struct_header_v5 *)pkt;
  struct struct_export_v5 *exp_v5;
  unsigned short int count = ntohs(hdr_v5->count);

  if (len < NfHdrV5Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;

  reset_mac(pptrs);

  if ((count <= V5_MAXFLOWS) && ((count*NfDataV5Sz)+NfHdrV5Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v5;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v5->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v5->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v5->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v5->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v5->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v5->dstport);
      }

      /* IP header's id field is unused; we will use it to transport our id */ 
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v5++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
} 

void process_v7_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
                struct plugin_requests *req)
{
  struct struct_header_v7 *hdr_v7 = (struct struct_header_v7 *)pkt;
  struct struct_export_v7 *exp_v7;
  unsigned short int count = ntohs(hdr_v7->count);

  if (len < NfHdrV7Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV7Sz;
  exp_v7 = (struct struct_export_v7 *)pkt;

  reset_mac(pptrs);

  if ((count <= V7_MAXFLOWS) && ((count*NfDataV7Sz)+NfHdrV7Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v7;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v7->srcaddr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v7->dstaddr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v7->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v7->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v7->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v7->dstport);
      }

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v7++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
}

void process_v8_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
                struct plugin_requests *req)
{
  struct struct_header_v8 *hdr_v8 = (struct struct_header_v8 *)pkt;
  unsigned char *exp_v8;
  unsigned short int count = ntohs(hdr_v8->count);

  if (len < NfHdrV8Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV8Sz;
  exp_v8 = pkt;

  reset_mac(pptrs);
  reset_ip4(pptrs);

  if ((count <= v8_handlers[hdr_v8->aggregation].max_flows) && ((count*v8_handlers[hdr_v8->aggregation].exp_size)+NfHdrV8Sz <= len)) {
    while (count) {
      pptrs->f_data = exp_v8;
      if (req->bpf_filter) v8_handlers[hdr_v8->aggregation].fh(pptrs, exp_v8);

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v8 += v8_handlers[hdr_v8->aggregation].exp_size;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent);
    return;
  }
}

void process_v9_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req)
{
  struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *)pkt;
  struct template_hdr_v9 *template_hdr;
  struct template_cache_entry *tpl;
  struct data_hdr_v9 *data_hdr;
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t fid, off = 0, flowoff, flowsetlen, flow_type; 

  if (len < NfHdrV9Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v9 packet", (struct sockaddr *) pptrsv->v4.f_agent);
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV9Sz;
  off += NfHdrV9Sz; 

  process_flowset:
  if (off+NfDataHdrV9Sz >= len) { 
    notify_malf_packet(LOG_INFO, "INFO: unable to read next Flowset; incomplete NetFlow v9 packet",
		    (struct sockaddr *) pptrsv->v4.f_agent);
    return;
  }

  data_hdr = (struct data_hdr_v9 *)pkt;
  fid = ntohs(data_hdr->flow_id);
  if (fid == 0) { /* template */ 
    template_hdr = (struct template_hdr_v9 *)pkt;
    flowsetlen = ntohs(template_hdr->flow_len);
    if (off+flowsetlen > len) { 
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Template Flowset; incomplete NetFlow v9 packet",
		      (struct sockaddr *) pptrsv->v4.f_agent);
      return;
    }

    handle_template_v9(template_hdr, pptrs);
    pkt += flowsetlen; 
    off += flowsetlen; 
  }
  else if (fid >= 256) { /* data */
    flowsetlen = ntohs(data_hdr->flow_len);
    if (off+flowsetlen > len) { 
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Data Flowset (incomplete NetFlow v9 packet)",
		      (struct sockaddr *) pptrsv->v4.f_agent);
      return;
    }

    flowoff = 0;
    pkt += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    tpl = find_template_v9(data_hdr->flow_id, pptrs);
    if (!tpl) {
      Log(LOG_DEBUG, "DEBUG ( default/core ): Discarded NetFlow V9 packet (R: unknown template '%u')\n", fid); 
      pkt += flowsetlen-NfDataHdrV9Sz;
      off += flowsetlen;
    }
    else {
      while (flowoff+tpl->len <= flowsetlen) {
        pptrs->f_data = pkt;
	pptrs->f_tpl = (u_char *) tpl;
	flow_type = NF_evaluate_flow_type(tpl, pptrs);

	/* we need to understand the IP protocol version in order to build the fake packet */ 
	switch (flow_type) {
	case NF9_FTYPE_IPV4:
	  if (req->bpf_filter) {
	    reset_mac(pptrs);
	    reset_ip4(pptrs);

            memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
            memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }

	  if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
          exec_plugins(pptrs);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_IPV6:
	  pptrsv->v6.f_header = pptrs->f_header;
	  pptrsv->v6.f_data = pptrs->f_data;
	  pptrsv->v6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac(&pptrsv->v6);
	    reset_ip6(&pptrsv->v6);
	    memcpy(pptrsv->v6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->v6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
            memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }

	  if (config.pre_tag_map) pptrsv->v6.tag = NF_find_id(&pptrsv->v6);
          exec_plugins(&pptrsv->v6);
	  break;
#endif
	case NF9_FTYPE_VLAN_IPV4:
	  pptrsv->vlan4.f_header = pptrs->f_header;
	  pptrsv->vlan4.f_data = pptrs->f_data;
	  pptrsv->vlan4.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan4); 
	    reset_ip4(&pptrsv->vlan4);

	    memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlan4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlan4.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  if (config.pre_tag_map) pptrsv->vlan4.tag = NF_find_id(&pptrsv->vlan4);
	  exec_plugins(&pptrsv->vlan4);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_VLAN_IPV6:
	  pptrsv->vlan6.f_header = pptrs->f_header;
	  pptrsv->vlan6.f_data = pptrs->f_data;
	  pptrsv->vlan6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan6);
	    reset_ip6(&pptrsv->vlan6);

	    memcpy(pptrsv->vlan6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlan6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlan6.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  if (config.pre_tag_map) pptrsv->vlan6.tag = NF_find_id(&pptrsv->vlan6);
	  exec_plugins(&pptrsv->vlan6);
	  break;
#endif
        case NF9_FTYPE_MPLS_IPV4:
          pptrsv->mpls4.f_header = pptrs->f_header;
          pptrsv->mpls4.f_data = pptrs->f_data;
          pptrsv->mpls4.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls4.mpls_ptr;
	    u_int32_t *label, idx;

            /* XXX: fix caplen */
            reset_mac(&pptrsv->mpls4);
            memcpy(pptrsv->mpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
            memcpy(pptrsv->mpls4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      label = (u_int32_t *) ptr;
	      *label = 0;
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->mpls4.iph_ptr = ptr;
	    pptrsv->mpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->mpls4);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
          }
          if (config.pre_tag_map) pptrsv->mpls4.tag = NF_find_id(&pptrsv->mpls4);
          exec_plugins(&pptrsv->mpls4);
          break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_MPLS_IPV6:
	  pptrsv->mpls6.f_header = pptrs->f_header;
	  pptrsv->mpls6.f_data = pptrs->f_data;
	  pptrsv->mpls6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls6.mpls_ptr;
	    u_int32_t *label, idx;

	    /* XXX: fix caplen */
	    reset_mac(&pptrsv->mpls6);
	    memcpy(pptrsv->mpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->mpls6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
            for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      label = (u_int32_t *) ptr;
	      *label = 0;
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->mpls6.iph_ptr = ptr;
	    pptrsv->mpls6.tlh_ptr = ptr + IP6HdrSz;
	    reset_ip6(&pptrsv->mpls6);
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  if (config.pre_tag_map) pptrsv->mpls6.tag = NF_find_id(&pptrsv->mpls6);
	  exec_plugins(&pptrsv->mpls6);
	  break;
#endif
        case NF9_FTYPE_VLAN_MPLS_IPV4:
	  pptrsv->vlanmpls4.f_header = pptrs->f_header;
	  pptrsv->vlanmpls4.f_data = pptrs->f_data;
	  pptrsv->vlanmpls4.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls4.mpls_ptr;
	    u_int32_t *label, idx;

	    /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls4);
	    memcpy(pptrsv->vlanmpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlanmpls4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlanmpls4.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      label = (u_int32_t *) ptr;
	      *label = 0;
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->vlanmpls4.iph_ptr = ptr;
	    pptrsv->vlanmpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->vlanmpls4);

            memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  if (config.pre_tag_map) pptrsv->vlanmpls4.tag = NF_find_id(&pptrsv->vlanmpls4);
	  exec_plugins(&pptrsv->vlanmpls4);
	  break;
#if defined ENABLE_IPV6
        case NF9_FTYPE_VLAN_MPLS_IPV6:
	  pptrsv->vlanmpls6.f_header = pptrs->f_header;
	  pptrsv->vlanmpls6.f_data = pptrs->f_data;
	  pptrsv->vlanmpls6.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls6.mpls_ptr;
            u_int32_t *label, idx;

            /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls6);
	    memcpy(pptrsv->vlanmpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlanmpls6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlanmpls6.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      label = (u_int32_t *) ptr;
	      *label = 0;
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->vlanmpls6.iph_ptr = ptr;
	    pptrsv->vlanmpls6.tlh_ptr = ptr + IP6HdrSz;
	    reset_ip6(&pptrsv->vlanmpls6);

	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  if (config.pre_tag_map) pptrsv->vlanmpls6.tag = NF_find_id(&pptrsv->vlanmpls6);
	  exec_plugins(&pptrsv->vlanmpls6);
	  break;
#endif
	default:
	  break;
        }

        pkt += tpl->len;
        flowoff += tpl->len;
      }

      pkt += flowsetlen-flowoff; /* handling padding */
      off += flowsetlen; 
    }
  }
  else { /* unsupported flowset */
    data_hdr = (struct data_hdr_v9 *)pkt;
    flowsetlen = ntohs(data_hdr->flow_len);
    if (off+flowsetlen > len) {
      Log(LOG_DEBUG, "DEBUG ( default/core ): unable to read unsupported Flowset (ID: '%u').\n", fid);
      return;
    }
    pkt += flowsetlen;
    off += flowsetlen;
  }

  if (off < len) goto process_flowset;
}

void load_allow_file(char *filename, struct hosts_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN];
  int index = 0;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core ): allow file '%s' not found\n", filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table)); 
    while (!feof(file)) {
      if (index >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */ 
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) { 
        if (!sanitize_buf(buf)) {
	  if (str_to_addr(buf, &t->table[index])) index++;
	  else Log(LOG_WARNING, "WARN ( default/core ): 'nfacctd_allow_file': Bad IP address '%s'. Ignored.\n", buf);
        }
      }
    }
    t->num = index;
  }
}

int check_allow(struct hosts_table *allow, struct sockaddr *sa)
{
  int index;

  for (index = 0; index < allow->num; index++) {
    if (((struct sockaddr *)sa)->sa_family == allow->table[index].family) {
      if (allow->table[index].family == AF_INET) {
        if (((struct sockaddr_in *)sa)->sin_addr.s_addr == allow->table[index].address.ipv4.s_addr)
          return TRUE;
      }
#if defined ENABLE_IPV6
      else if (allow->table[index].family == AF_INET6) {
        if (!ip6_addr_cmp(&(((struct sockaddr_in6 *)sa)->sin6_addr), &allow->table[index].address.ipv6))
          return TRUE;
      }
#endif
    }
  }
  
  return FALSE;
}

void compute_once()
{
  NBO_One = htonl(1);
  PdataSz = sizeof(struct pkt_data);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  NfHdrV1Sz = sizeof(struct struct_header_v1);
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV7Sz = sizeof(struct struct_header_v7);
  NfHdrV8Sz = sizeof(struct struct_header_v8);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfDataV1Sz = sizeof(struct struct_export_v1);
  NfDataV5Sz = sizeof(struct struct_export_v5);
  NfDataV7Sz = sizeof(struct struct_export_v7);
  IP4HdrSz = sizeof(struct my_iphdr);
  IP4TlSz = sizeof(struct my_iphdr)+sizeof(struct my_tlhdr);

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct my_tlhdr);
#endif
}

u_int16_t NF_evaluate_flow_type(struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  u_int8_t ret=0;

  if (tpl->tpl[NF9_SRC_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_SRC_VLAN].off) > 0) ret += NF9_FTYPE_VLAN; 
  if (tpl->tpl[NF9_MPLS_LABEL_1].len /* check: value > 0 ? */) ret += NF9_FTYPE_MPLS; 
  if (!tpl->tpl[NF9_IP_PROTOCOL_VERSION].len || *(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 4);
  else if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 6) ret += NF9_FTYPE_IPV6; 

  return ret;
}

void reset_mac(struct packet_ptrs *pptrs)
{
  memset(pptrs->mac_ptr, 0, 2*ETH_ADDR_LEN);
}

void reset_mac_vlan(struct packet_ptrs *pptrs)
{
  u_int16_t *vlan_id = (u_int16_t *) pptrs->vlan_ptr;

  memset(pptrs->mac_ptr, 0, 2*ETH_ADDR_LEN);
  *vlan_id = 0;
}

void reset_ip4(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP4TlSz);
  Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_vhl, 5);
}

#if defined ENABLE_IPV6
void reset_ip6(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP6TlSz);  
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_hlim, htons(64));
}
#endif

void notify_malf_packet(short int severity, char *ostr, struct sockaddr *sa)
{
  struct host_addr a;
  u_char errstr[SRVBUFLEN];
  u_char agent_addr[50] /* able to fit an IPv6 string aswell */, any[]="0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr(sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);
  if (!config.nfacctd_ip) config.nfacctd_ip = any;
  snprintf(errstr, SRVBUFLEN, "%s: nfacctd=%s:%u agent=%s:%u \n",
  ostr, config.nfacctd_ip, config.nfacctd_port, agent_addr, agent_port);
  Log(severity, errstr);
}

int NF_find_id(struct packet_ptrs *pptrs)
{
  struct id_table *t = (struct id_table *)pptrs->idtable;
  int x, j, id, stop;

  /* The id_table is shared between by IPv4 and IPv6 NetFlow agents.
     IPv4 ones are in the lower part (0..x), IPv6 ones are in the upper
     part (x+1..end)
  */

  id = 0;
  if (((struct sockaddr *)pptrs->f_agent)->sa_family == AF_INET) {
    for (x = 0; x < t->ipv4_num; x++) {
      if (t->e[x].agent_ip.address.ipv4.s_addr == ((struct sockaddr_in *)pptrs->f_agent)->sin_addr.s_addr) {
        for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
        if (id) break;
      }
      else if (t->e[x].agent_ip.address.ipv4.s_addr > ((struct sockaddr_in *)pptrs->f_agent)->sin_addr.s_addr) break;
    }
  }
#if defined ENABLE_IPV6
  else if (((struct sockaddr *)pptrs->f_agent)->sa_family == AF_INET6) {
    for (x = (t->num-t->ipv6_num); x < t->num; x++) {
      if (!ip6_addr_cmp(&t->e[x].agent_ip.address.ipv6, (&((struct sockaddr_in6 *)pptrs->f_agent)->sin6_addr))) {
        for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
        if (id) break;
      }
      else if (ip6_addr_cmp(&t->e[x].agent_ip.address.ipv6, (&((struct sockaddr_in6 *)pptrs->f_agent)->sin6_addr)) > 0)
        break;
    }
  }
#endif
  return id;
}

