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
#define __PMACCTD_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "pretag_handlers.h"
#include "pretag-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_frag.h"
#include "ip_flow.h"

/* variables to be exported away */
int debug;
struct configuration config; /* global configuration */ 
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */ 
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
int have_num_memory_pools; /* global getopt() stuff */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
u_char dummy_tlhdr[16];

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s\n", PMACCTD_USAGE_HEADER);
  printf("Usage: %s [-D|-d] [-i interface] [-c primitive[,...]] [-P plugin[,...]] [filter]\n", prog_name);
  printf("       %s [-f config_file]\n", prog_name);
  printf("       %s [-h]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tshow this page\n");
  printf("  -f  \tconfiguration file (see also CONFIG-KEYS)\n");
  printf("  -c  \t[src_mac|dst_mac|vlan|src_host|dst_host|src_net|dst_net|src_port|dst_port|proto|tos|src_as|dst_as, \n\t ,sum_mac,sum_host,sum_net,sum_as,sum_port,tag,flows,none] \n\taggregation primitives and flows (DEFAULT: src_host)\n");
  printf("  -D  \tdaemonize\n"); 
  printf("  -N  \tdisable promiscuous mode\n");
  printf("  -n  \tpath to a file containing network definitions\n");
  printf("  -o  \tpath to a file containing port definitions\n");
  printf("  -P  \t[memory|print|mysql|pgsql] \n\tactivate plugin\n"); 
  printf("  -d  \tenable debug\n");
  printf("  -i  \tlistening interface\n");
  printf("  -I  \tread packets from the specified savefile\n");
  printf("  -S  \t[auth|mail|daemon|kern|user|local[0-7]] \n\tsyslog facility\n");
  printf("  -F  \twrite Core Process PID into the specified file\n");
  printf("  -w  \twait for the listening interface to become available\n");
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
  printf("  Daemonize the process; listen on eth0; write stats in a MySQL database\n"); 
  printf("  pmacctd -c src_host,dst_host -i eth0 -D -P mysql\n\n");
  printf("  Print flows over the screen; listen on ee1; refresh data every 30 seconds\n");
  printf("  pmacctd -c src_host,dst_host,proto -P print -i ee1 -r 30\n");
  printf("\n");
  printf("  See EXAMPLES for further hints\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv)
{
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  struct bpf_program filter;
  struct pcap_device device;
  char errbuf[PCAP_ERRBUF_SIZE];
  int index, logf;

  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];
  int psize = DEFAULT_SNAPLEN;

  struct id_table idt;
  struct pcap_callback_data cb_data;

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
  memset(&device, 0, sizeof(struct pcap_device));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&req, 0, sizeof(req));
  memset(dummy_tlhdr, 0, sizeof(dummy_tlhdr));
  config.acct_type = ACCT_PM;

  rows = 0;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCTD)) != -1)) {
    cfg[rows] = malloc(SRVBUFLEN);
    switch (cp) {
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
    case 'N':
      strcpy(cfg[rows], "promisc: false");
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
    case 'i':
      strcpy(cfg[rows], "interface: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'I':
      strcpy(cfg[rows], "pcap_savefile: ");
      strncat(cfg[rows], optarg, CFG_LINE_LEN(cfg[rows]));
      rows++;
      break;
    case 'w':
      strcpy(cfg[rows], "interface_wait: true");
      rows++;
      break;
    case 'L':
      strcpy(cfg[rows], "snaplen: ");
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
      config.acct_type = ACCT_PM;
      break;
    }
    list = list->next;
  }

  /* Let's check whether we need superuser privileges */
  if (config.snaplen) psize = config.snaplen;

  if (!config.pcap_savefile) {
    if (getuid() != 0) {
      printf("%s\n\n", PMACCTD_USAGE_HEADER);
      printf("ERROR: You need superuser privileges to run this command.\nExiting ...\n\n");
      exit(1);
    }
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

  if (config.pidfile) write_pid_file(config.pidfile);

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (strcmp(list->type.string, "core")) {
      evaluate_sums(&list->cfg.what_to_count, list->name, list->type.string);
      if (list->cfg.what_to_count & (COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_SUM_PORT))
	config.handle_fragments = TRUE;
      if (list->cfg.what_to_count & COUNT_FLOWS) {
	config.handle_fragments = TRUE;
	config.handle_flows = TRUE;
      }
      if (!list->cfg.what_to_count) {
	Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	list->cfg.what_to_count |= COUNT_SRC_HOST;
      }
      if ((list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) && !list->cfg.networks_file) { 
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

  if (config.handle_fragments) init_ip_fragment_handler();
  if (config.handle_flows) init_ip_flow_handler();

  /* If any device/savefile have been specified, choose a suitable device
     where to listen for traffic */ 
  if (!config.dev && !config.pcap_savefile) {
    Log(LOG_WARNING, "WARN ( default/core ): Selecting a suitable device.\n");
    config.dev = pcap_lookupdev(errbuf); 
    if (!config.dev) {
      Log(LOG_WARNING, "WARN ( default/core ): Unable to find a suitable device. Exiting.\n");
      exit(1);
    }
  }

  /* reading filter; if it exists, we'll take an action later */
  if (!strlen(config_file)) config.clbuf = copy_argv(&argv[optind]);

  if (config.dev && config.pcap_savefile) {
    Log(LOG_ERR, "ERROR ( default/core ): 'interface' (-i) and 'pcap_savefile' (-I) directives are mutually exclusive. Exiting.\n");
    exit(1); 
  }

  throttle_startup:
  if (config.dev) {
    if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL) {
      if (!config.if_wait) {
        Log(LOG_ERR, "ERROR ( default/core ): pcap_open_live(): %s\n", errbuf);
        exit(1);
      }
      else {
        sleep(5); /* XXX: user defined ? */
        goto throttle_startup;
      }
    } 
  }
  else if (config.pcap_savefile) {
    if ((device.dev_desc = pcap_open_offline(config.pcap_savefile, errbuf)) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core ): pcap_open_offline(): %s\n", errbuf);
      exit(1);
    }
  }

  device.active = TRUE;
  glob_pcapt = device.dev_desc; /* SIGINT/stats handling */ 
  if (config.pipe_size) {
    int slen = sizeof(config.pipe_size), x;

#if defined (PCAP_TYPE_linux) || (PCAP_TYPE_snoop)
    Setsocksize(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &config.pipe_size, slen);
    getsockopt(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &x, &slen);
    Log(LOG_DEBUG, "DEBUG ( default/core ): PCAP buffer: obtained %d / %d bytes.\n", x, config.pipe_size);
#endif
  }

  device.link_type = pcap_datalink(device.dev_desc); 
  for (index = 0; _devices[index].link_type != -1; index++) {
    if (device.link_type == _devices[index].link_type)
      device.data = &_devices[index];
  }

  /* we need to solve some link constraints */
  if (device.data == NULL) {
    Log(LOG_ERR, "ERROR ( default/core ): data link not supported: %d\n", device.link_type); 
    exit(1);
  }
  else Log(LOG_INFO, "OK ( default/core ): link type is: %d\n", device.link_type); 

  if (device.link_type != DLT_EN10MB) {
    list = plugins_list;
    while (list) {
      if ((list->cfg.what_to_count & COUNT_SRC_MAC) || (list->cfg.what_to_count & COUNT_DST_MAC)) {
        Log(LOG_ERR, "ERROR ( default/core ): MAC aggregation not available for link type: %d\n", device.link_type);
        exit(1);
      }
      list = list->next;
    }
  }

  cb_data.device = &device;
  
  /* doing pcap stuff */
  if (pcap_lookupnet(config.dev, &localnet, &netmask, errbuf) < 0) {
    localnet = 0;
    netmask = 0;
    Log(LOG_WARNING, "WARN ( default/core ): %s\n", errbuf);
  }

  if (pcap_compile(device.dev_desc, &filter, config.clbuf, 0, netmask) < 0)
    Log(LOG_WARNING, "WARN: %s\nWARN ( default/core ): going on without a filter\n", pcap_geterr(device.dev_desc));
  else {
    if (pcap_setfilter(device.dev_desc, &filter) < 0)
      Log(LOG_WARNING, "WARN: %s\nWARN ( default/core ): going on without a filter\n", pcap_geterr(device.dev_desc));
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* loading pre-tagging map, if any */
  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt, &req);
    cb_data.idt = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    cb_data.idt = NULL; 
  }

  /* plugins glue: creation */
  load_plugins(&device, &req);
  evaluate_packet_handlers();

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  if (!config.daemon) signal(SIGINT, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);
  
  /* When reading packets in a savefile, things are lightning fast; we will sit 
     here just few seconds, thus allowing plugins to complete their startup operations */ 
  if (config.pcap_savefile) sleep(2);

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for(;;) {
    if (!device.active) {
      Log(LOG_WARNING, "WARN ( default/core ): %s has become unavailable; throttling ...\n", config.dev);
      throttle_loop:
      sleep(5); /* XXX: user defined ? */
      if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL)
        goto throttle_loop;
      pcap_setfilter(device.dev_desc, &filter);
      device.active = TRUE;
    }
    pcap_loop(device.dev_desc, -1, pcap_cb, (u_char *) &cb_data);
    pcap_close(device.dev_desc);

    if (config.pcap_savefile) {
      Log(LOG_INFO, "INFO ( default/core ): finished reading the specified savefile. Exiting in few seconds ...\n"); 
      sleep(5);
      stop_all_childs();
    }
    device.active = FALSE;
  }
}

void pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct packet_ptrs pptrs;
  struct pcap_callback_data *cb_data = (struct pcap_callback_data *) user;
  struct pcap_device *device = cb_data->device; 

  /* We process the packet with the appropriate
     data link layer function */
  if (buf) {
    pptrs.pkthdr = (struct pcap_pkthdr *) pkthdr;
    pptrs.packet_ptr = (u_char *) buf;
    pptrs.mac_ptr = 0; pptrs.vlan_ptr = 0; pptrs.mpls_ptr = 0;
    pptrs.pf = 0;
    pptrs.idtable = cb_data->idt;
    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {
	if (config.pre_tag_map) pptrs.tag = PM_find_id(&pptrs);
	exec_plugins(&pptrs); 
      }
    }
  }
} 

int ip_handler(register struct packet_ptrs *pptrs)
{
  register u_int8_t len = 0;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  register unsigned char *ptr;
  register u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr;
  u_int8_t *tcp_flags;
  int ret = TRUE;

  /* len: number of 32bit words forming the header */
  len = IP_HL(((struct my_iphdr *) pptrs->iph_ptr));
  len <<= 2;
  ptr = pptrs->iph_ptr+len;
  off += len;

  /* check len */
  if (off > caplen) return FALSE; /* IP packet truncated */
  pptrs->l4_proto = ((struct my_iphdr *)pptrs->iph_ptr)->ip_p;
  
  /* check fragments if needed */
  if (config.handle_fragments) {
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
	Log(LOG_INFO, "INFO ( default/core ): short IPv4 packet read (%u/%u/frags). Snaplen issue ?\n", caplen, off+MyTLHdrSz);
	return FALSE; 
      }
      pptrs->tlh_ptr = ptr; 
    
      if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_MF|IP_OFFMASK)) {
        ret = ip_fragment_handler(pptrs);
	if (!ret) goto quit;
      }
    }
    else pptrs->tlh_ptr = dummy_tlhdr;

    if (config.handle_flows) { 
      pptrs->is_closing = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
        if (off+TCPFlagOff+1 > caplen) {
	  Log(LOG_INFO, "INFO ( default/core ): short IPv4 packet read (%u/%u/flows). Snaplen issue ?\n", caplen, off+TCPFlagOff+1); 
	  return FALSE; 
	}
        tcp_flags = (u_int8_t *)pptrs->tlh_ptr+TCPFlagOff;
	if (*tcp_flags & TH_FIN) pptrs->is_closing = FL_TCPFIN;
	if (*tcp_flags & TH_RST) pptrs->is_closing = FL_TCPRST;
      }

      pptrs->new_flow = ip_flow_handler(pptrs);
    }
  }

  quit:
  return ret;
}

#if defined ENABLE_IPV6
int ip6_handler(register struct packet_ptrs *pptrs)
{
  struct ip6_frag *fhdr = NULL;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  u_int16_t len = 0, plen = ntohs(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen);
  u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr;
  u_int32_t advance;
  u_int8_t nh, fragmented = 0, *tcp_flags; 
  u_char *ptr = pptrs->iph_ptr;
  int ret = TRUE;

  /* length checks */
  if (off+IP6HdrSz > caplen) return FALSE; /* IP packet truncated */
  if (plen == 0) { 
    Log(LOG_INFO, "INFO ( default/core ): NULL IPv6 payload length. Jumbo packets are currently not supported.\n");
    return FALSE;
  }

  pptrs->l4_proto = 0;
  nh = ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_nxt; 
  advance = IP6HdrSz;
  
  while ((off+advance <= caplen) && advance) {
    off += advance;
    ptr += advance;

    switch(nh) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_MOBILITY:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = (((struct ip6_ext *)ptr)->ip6e_len + 1) << 3; 
      break;
    case IPPROTO_AH:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ah)+(((struct ah *)ptr)->ah_len << 2); /* hdr + sumlen */
      break;
    case IPPROTO_FRAGMENT:
      fhdr = (struct ip6_frag *) ptr;
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ip6_frag);
      break;
    /* XXX: case IPPROTO_ESP: */
    /* XXX: case IPPROTO_IPCOMP: */
    default:
      pptrs->tlh_ptr = ptr;
      pptrs->l4_proto = nh;
      goto end;
    }
  }

  end:

  if (config.handle_fragments) { 
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
	Log(LOG_INFO, "INFO ( default/core ): short IPv6 packet read (%u/%u/frags). Snaplen issue ?\n", caplen, off+MyTLHdrSz);
	return FALSE;
      }

      if (fhdr && (fhdr->ip6f_offlg & htons(IP6F_MORE_FRAG|IP6F_OFF_MASK))) {
        ret = ip6_fragment_handler(pptrs, fhdr);
	if (!ret) goto quit;
      }
    }
    else pptrs->tlh_ptr = dummy_tlhdr;

    if (config.handle_flows) {
      pptrs->is_closing = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
	if (off+TCPFlagOff+1 > caplen) {
	  Log(LOG_INFO, "INFO ( default/core ): short IPv6 packet read (%u/%u/flows). Snaplen issue ?\n", caplen, off+TCPFlagOff+1);
	  return FALSE;
	}
	tcp_flags = (u_int8_t *)pptrs->tlh_ptr+TCPFlagOff;
	if (*tcp_flags & TH_FIN) pptrs->is_closing = FL_TCPFIN;
	if (*tcp_flags & TH_RST) pptrs->is_closing = FL_TCPRST;
      }

      pptrs->new_flow = ip_flow6_handler(pptrs);
    }
  }

  quit:
  return TRUE;
}
#endif

int PM_find_id(struct packet_ptrs *pptrs)
{
  struct id_table *t = (struct id_table *)pptrs->idtable;
  int x, j, id, stop;

  id = 0;
  for (x = 0; x < t->ipv4_num; x++) {
    for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
    if (id) break;
  }

  return id;
}

void compute_once()
{
  NBO_One = htonl(1);
  PdataSz = sizeof(struct pkt_data);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  IP4HdrSz = sizeof(struct my_iphdr);
  MyTLHdrSz = sizeof(struct my_tlhdr);
  TCPFlagOff = 13;
#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
#endif
}
