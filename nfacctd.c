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
  printf("Usage: %s [-D|-d] [-l port] [-c primitive[,...]] [-P plugin[,...]]\n", prog_name);
  printf("       %s [-f config_file]\n", prog_name);
  printf("       %s [-h]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tshow this page\n");
  printf("  -l  \tlisten on the specified UDP port\n");
  printf("  -f  \tconfiguration file (see also CONFIG-KEYS)\n");
  printf("  -c  \t[src_mac|dst_mac|vlan|src_host|dst_host|src_net|dst_net|src_port|dst_port|tos|proto|src_as|dst_as, \n\t ,sum_host,sum_net,sum_as,sum_port,tag,none] \n\taggregation primitives (DEFAULT: src_host)\n");
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
  printf("  -v  \t[1|2] \n\ttable version\n");
  printf("\n");
  printf("Examples:\n");
  printf("  Daemonize the process; listen on eth0; write stats in a MySQL database\n");
  printf("  nfacctd -c src_host,dst_host -i eth0 -D -P mysql\n\n");
  printf("  Print flows over the screen; listen on ee1; refresh data every 30 seconds\n");
  printf("  nfacctd -c src_host,dst_host,proto -P print -i ee1 -r 30\n");
  printf("\n");
  printf("  See EXAMPLES for further hints\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  struct packet_ptrs pptrs;
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
  struct pcap_pkthdr dummy_pkthdr;

#if defined ENABLE_IPV6
  struct packet_ptrs pptrs6;
  unsigned char dummy_packet6[92]; 
  struct pcap_pkthdr dummy_pkthdr6;
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

  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&pptrs, 0, sizeof(pptrs));
  config.acct_type = ACCT_NF;

  rows = 0;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_NFACCTD)) != -1)) {
    cfg[rows] = malloc(SRVBUFLEN);
    switch (cp) {
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
      Log(LOG_WARNING, "WARN: specified syslog facility is not supported; logging to console.\n");
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO: Start logging ...\n");
  }

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (strcmp(list->type.string, "core")) {  
      evaluate_sums(&list->cfg.what_to_count);
      if (!list->cfg.what_to_count) {
	Log(LOG_WARNING, "WARN: defaulting to SRC HOST aggregation in '%s-%s'.\n", list->name, list->type.string);
	list->cfg.what_to_count |= COUNT_SRC_HOST;
      }
      else if (list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_NET|COUNT_SUM_AS)) {
        if (!list->cfg.networks_file) {
	  if ((list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) && (!(list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET)))
	      && (list->cfg.nfacctd_as == NF_AS_KEEP));
	  else {
            Log(LOG_ERR, "ERROR: NET/AS aggregation has been selected but NO networks file has been specified. Exiting...\n\n");
	    exit(1);
	  }
	}
	else {
	  if (((list->cfg.what_to_count & COUNT_SRC_NET) && (list->cfg.what_to_count & COUNT_SRC_AS)) ||
	     ((list->cfg.what_to_count & COUNT_DST_NET) && (list->cfg.what_to_count & COUNT_DST_AS))) {
	    Log(LOG_ERR, "ERROR: NET/AS are mutually exclusive. Exiting...\n\n");
	    exit(1);
	  }
	}
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
  if (!config.nfacctd_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in);
  }
  else {
    trim_spaces(config.nfacctd_ip);
    ret = str_to_addr(config.nfacctd_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR: 'nfacctd_ip' value is not valid. Exiting.\n");
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
  }

  /* socket creation */
  sd = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
  if (sd < 0) {
    Log(LOG_ERR, "ERROR: socket() failed.\n");
    exit(1);
  }

  /* bind socket to port */
  rc = Setsocksize(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN: Setsocksize() failed for SO_REUSEADDR.\n");

  if (config.pipe_size) {
    rc = Setsocksize(sd, SOL_SOCKET, SO_RCVBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_ERR, "WARN: Setsocksize() failed for 'plugin_pipe_size' = '%d'.\n", config.pipe_size); 
  }

  rc = bind(sd, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR: bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.nfacctd_ip, config.nfacctd_port, errno);
    exit(1);
  }

  if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);
  else memset(&allow, 0, sizeof(allow));

  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt);
    pptrs.idtable = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    pptrs.idtable = NULL;
  }

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

  pptrs.f_agent = (u_char *) &client;
  pptrs.packet_ptr = dummy_packet;
  pptrs.pkthdr = &dummy_pkthdr;
  Assign16(((struct eth_header *)pptrs.packet_ptr)->ether_type, htons(ETHERTYPE_IP)); /* 0x800 */
  pptrs.iph_ptr = pptrs.packet_ptr + ETHER_HDRLEN; 
  pptrs.tlh_ptr = pptrs.packet_ptr + ETHER_HDRLEN + sizeof(struct my_iphdr); 
  pptrs.pkthdr->caplen = 38; /* eth_header + my_iphdr + my_tlhdr */
  pptrs.pkthdr->len = 100; /* fake len */ 
  Assign8(((struct my_iphdr *)pptrs.iph_ptr)->ip_vhl, 5);
  pptrs.l3_proto = ETHERTYPE_IP;

#if defined ENABLE_IPV6
  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  memset(&pptrs6, 0, sizeof(pptrs6));

  pptrs6.idtable = pptrs.idtable;
  pptrs6.f_agent = (u_char *) &client;
  pptrs6.packet_ptr = dummy_packet6;
  pptrs6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs6.iph_ptr = pptrs6.packet_ptr + ETHER_HDRLEN;
  pptrs6.tlh_ptr = pptrs6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  pptrs6.pkthdr->caplen = 60; /* eth_header + ip6_hdr + my_tlhdr */
  pptrs6.pkthdr->len = 100; /* fake len */
  Assign16(((struct ip6_hdr *)pptrs6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs6.iph_ptr)->ip6_hlim, htons(64));
  pptrs6.l3_proto = ETHERTYPE_IPV6;
#endif

  if (config.debug) Log(LOG_DEBUG, "DEBUG: waiting for data on UDP port '%u'\n", config.nfacctd_port);
  allowed = TRUE;

  /* Main loop */
  for(;;) {
    memset(netflow_packet, 0, NETFLOW_MSG_SIZE);
    ret = recvfrom(sd, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);

    /* check if Hosts Allow Table is loaded; if it is, we will
       enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    /* We will change byte ordering in order to avoid a bunch
       of ntohs() calls */
    ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);
    
    switch(((struct struct_header_v5 *)netflow_packet)->version) {
    case 1:
      process_v1_packet(netflow_packet, ret, &pptrs, &req);
      break;
    case 5:
      process_v5_packet(netflow_packet, ret, &pptrs, &req); 
      break;
    case 9:
#if defined ENABLE_IPV6
      process_v9_packet(netflow_packet, ret, &pptrs, &pptrs6, &req);
#else
      process_v9_packet(netflow_packet, ret, &pptrs, NULL, &req);
#endif
      break;
    default:
      /* We should notify the protocol version is not supported */
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
    if (config.debug) Log(LOG_INFO, "INFO: discarding short NetFlow v1 packet.\n");
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV1Sz; 
  exp_v1 = (struct struct_export_v1 *)pkt;

  if ((count <= V1_MAXFLOWS) && ((count*NfDataV1Sz)+NfHdrV1Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v1;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v1->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v1->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v1->prot);
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
    if (config.debug) Log(LOG_INFO, "INFO: discarding malformed NetFlow v1 packet.\n");
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
    if (config.debug) Log(LOG_INFO, "INFO: discarding short NetFlow v5 packet.\n");
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;

  if ((count <= V5_MAXFLOWS) && ((count*NfDataV5Sz)+NfHdrV5Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v5;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v5->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v5->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v5->prot);
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
    if (config.debug) Log(LOG_INFO, "INFO: discarding malformed NetFlow v5 packet.\n");
    return;
  }
} 

void process_v9_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct packet_ptrs *pptrs6, struct plugin_requests *req)
{
  struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *)pkt;
  struct template_hdr_v9 *template_hdr;
  struct template_cache_entry *tpl;
  struct data_hdr_v9 *data_hdr;
  u_int16_t fid, off = 0, flowoff, flowsetlen; 

  if (len < NfHdrV9Sz) {
    if (config.debug) Log(LOG_INFO, "INFO: discarding short NetFlow v9 packet.\n");
    return;
  }
  pptrs->f_header = pkt;
#if defined ENABLE_IPV6
  pptrs6->f_header = pkt;
#endif
  pkt += NfHdrV9Sz;
  off += NfHdrV9Sz; 

  process_flowset:
  if (off+NfDataHdrV9Sz >= len) { 
    if (config.debug) Log(LOG_INFO, "INFO: unable to read next Flowset; incomplete NetFlow v9 packet.\n");
    return;
  }

  data_hdr = (struct data_hdr_v9 *)pkt;
  fid = ntohs(data_hdr->flow_id);
  if (fid == 0) { /* template */ 
    template_hdr = (struct template_hdr_v9 *)pkt;
    flowsetlen = ntohs(template_hdr->flow_len);
    if (off+flowsetlen > len) { 
      if (config.debug) Log(LOG_INFO, "INFO: unable to read next Template Flowset; incomplete NetFlow v9 packet.\n");
      return;
    }

    handle_template_v9(template_hdr, pptrs);
    pkt += flowsetlen; 
    off += flowsetlen; 
  }
  else if (fid >= 256) { /* data */
    // data_hdr = (struct data_hdr_v9 *)pkt;
    flowsetlen = ntohs(data_hdr->flow_len);
    if (off+flowsetlen > len) { 
      if (config.debug) Log(LOG_INFO, "INFO: unable to read next Data Flowset (ID: '%u'); incomplete NetFlow v9 packet.\n", fid);
      return;
    }

    flowoff = 0;
    pkt += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    tpl = find_template_v9(data_hdr->flow_id, pptrs);
    if (!tpl) {
      if (config.debug) Log(LOG_DEBUG, "DEBUG: Discarded NetFlow V9 packet (R: unknown template '%u')\n", fid); 
      pkt += flowsetlen-NfDataHdrV9Sz;
      off += flowsetlen;
    }
    else {
      while (flowoff+tpl->len <= flowsetlen) {
        pptrs->f_data = pkt;
	pptrs->f_tpl = (u_char *) tpl;

	/* we need to understand the IP protocol version in order to build the fake packet */ 
	if (!tpl->tpl[NF9_IP_PROTOCOL_VERSION].len || *(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 4) {
	  if (req->bpf_filter) {
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }

	  if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
          exec_plugins(pptrs);
        }
#if defined ENABLE_IPV6
        else if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 6) {
	  pptrs6->f_data = pkt;
	  pptrs6->f_tpl = (u_char *) tpl;

	  if (req->bpf_filter) {
            memcpy(&((struct ip6_hdr *)pptrs6->iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrs6->iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrs6->iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_tlhdr *)pptrs6->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrs6->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }

	  if (config.pre_tag_map) pptrs6->tag = NF_find_id(pptrs6);
          exec_plugins(pptrs6);
	}
#endif

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
      if (config.debug) Log(LOG_INFO, "INFO: unable to read next unsupported Flowset (ID: '%u'); incomplete NetFlow v9 packet.\n", fid);
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
      Log(LOG_ERR, "ERROR: allow file '%s' not found\n", filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table)); 
    while (!feof(file)) {
      if (index >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */ 
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) { 
        if (!sanitize_buf(buf)) {
	  if (str_to_addr(buf, &t->table[index])) index++;
	  else Log(LOG_WARNING, "WARN: 'nfacctd_allow_file': Bad IP address '%s'. Ignored.\n", buf);
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

void compute_once()
{
  NBO_One = htonl(1);
  PdataSz = sizeof(struct pkt_data);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  NfHdrV1Sz = sizeof(struct struct_header_v1);
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfDataV1Sz = sizeof(struct struct_export_v1);
  NfDataV5Sz = sizeof(struct struct_export_v5);

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
#endif
}

