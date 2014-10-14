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

/* defines */
#define __PMACCTD_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_frag.h"

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
  printf("%s\n", PMACCTD_USAGE_HEADER);
  printf("Usage: %s [-D] [-b buckets] [-i interface] [filter]\n", prog_name);
  printf("       %s [-f config_file]\n", prog_name);
  printf("       %s [-h]\n", prog_name);
  printf("\n-GENERAL- options:\n");
  printf("  -f  \tspecify a configuration file (see CONFIG-KEYS file for the valid config keys list)\n");
  printf("  -c  \t[src_mac|dst_mac|vlan|src_host|dst_host|src_net|dst_net|sum|src_port|dst_port|proto] \n\tcounts source, destination or total IP traffic (default src_host)\n");
  printf("  -D  \tdaemonize the process\n"); 
  printf("  -N  \tdon't use promiscuous mode\n");
  printf("  -n  \tpath for the file containing network definitions; to be used in conjunction with 'src_net' or 'dst_net'\n");
  printf("  -P  \t[memory|print|mysql|pgsql] \n\tactivate specified plugins\n"); 
  printf("  -d  \tenables debug mode\n");
  printf("  -i  \tinterface used for listening\n");
  printf("  -S  \t[auth|mail|daemon|kern|user|local[0-7]] \n\tenables syslog logging to the specified facility\n");
  printf("  -F  \twrites 'core' process PID into the specified file\n");
  printf("\n-MEMORY PLUGIN- options\n");
  printf("  -p  \tpath for client-server communication\n");
  printf("  -b  \tnumber of buckets\n");
  printf("  -m  \tnumbers of memory pools\n");
  printf("  -s  \tsize of each memory pool\n");
  printf("\n-PgSQL and MySQL PLUGINS- options\n");
  printf("  -r  \trefresh time of data into SQL database from in-memory cache (in seconds)\n");
  printf("  -v  \tSQL table version\n");
  printf("\n");
  printf("  -h  \tprints this page\n");
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
  int index, logf, ret;

  struct plugins_list_entry *list;
  char config_file[SRVBUFLEN];
  int psize = DEFAULT_SNAPLEN;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp; 

  if (getuid() != 0) { 
    printf("%s\n\n", PMACCTD_USAGE_HEADER);
    printf("ERROR: You need superuser privileges to run this command.\nExiting ...\n\n");
    exit(1);
  }

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  have_num_memory_pools = FALSE;
  errflag = 0;

  memset(&config, 0, sizeof(struct configuration));
  memset(&device, 0, sizeof(struct pcap_device));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
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

  if (config.pidfile) write_pid_file(config.pidfile);

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (list->cfg.post_tag) list->cfg.what_to_count |= COUNT_ID; /* sanity checks will follow later */ 
    if (strcmp(list->type.string, "core")) {
      if (((list->cfg.what_to_count & COUNT_SRC_PORT) || (list->cfg.what_to_count & COUNT_DST_PORT)) && !config.handle_fragments) {
	config.handle_fragments = TRUE;
	init_ip_fragment_handler();
      }
      if (list->cfg.what_to_count & COUNT_SUM_HOST) {
        if (list->cfg.what_to_count != COUNT_SUM_HOST) {
          config.what_to_count = COUNT_SUM_HOST;
          Log(LOG_WARNING, "WARN: using *only* sum aggregation method in '%s-%s'.\n", list->name, list->type.string);
	}
      }
      else if (!list->cfg.what_to_count) {
	Log(LOG_WARNING, "WARN: defaulting to src_host aggregation in '%s-%s'.\n", list->name, list->type.string);
	list->cfg.what_to_count = COUNT_SRC_HOST;
      }
      else if ((list->cfg.what_to_count & COUNT_SRC_NET) || (list->cfg.what_to_count & COUNT_DST_NET)) {
	if (!list->cfg.networks_file) {
	  Log(LOG_ERR, "ERROR: net aggregation method has been selected but no networks file specified. Exiting...\n\n");
	  exit(1);
	}
	else {
	  if (list->cfg.what_to_count & COUNT_SRC_NET) list->cfg.what_to_count |= COUNT_SRC_HOST;
	  if (list->cfg.what_to_count & COUNT_DST_NET) list->cfg.what_to_count |= COUNT_DST_HOST;
	}
      }
    } 
    list = list->next;
  }

  if (!config.dev) {
    Log(LOG_WARNING, "WARN: selecting a suitable device.\n");
    config.dev = pcap_lookupdev(errbuf); 
    if (!config.dev) {
      Log(LOG_WARNING, "WARN: unable to find a suitable device. Exiting ...\n");
      exit(1);
    }
  }

  /* reading filter; if it exists, we'll take an action later */
  if (!strlen(config_file)) config.clbuf = copy_argv(&argv[optind]);

  /* starting the wheel */
  if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL) {
    Log(LOG_ERR, "ERROR: pcap_open_live(): %s\n", errbuf);
    exit(1);
  } 
  device.active = TRUE;
  glob_pcapt = device.dev_desc; /* SIGINT/stats handling */ 
  if (config.pipe_size) {
    int slen = sizeof(config.pipe_size), x;

#if defined (PCAP_TYPE_linux) || (PCAP_TYPE_snoop)
    Setsocksize(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &config.pipe_size, slen);
    getsockopt(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &x, &slen);
    if (config.debug) Log(LOG_DEBUG, "DEBUG: PCAP buffer: obtained %d / %d bytes.\n", x, config.pipe_size);
#endif
  }

  device.link_type = pcap_datalink(device.dev_desc); 
  for (index = 0; _devices[index].link_type != -1; index++) {
    if (device.link_type == _devices[index].link_type)
      device.data = &_devices[index];
  }

  /* we need to solve some link constraints */
  if (device.data == NULL) {
    Log(LOG_ERR, "ERROR: data link not supported: %d\n", device.link_type); 
    exit(1);
  }
  else Log(LOG_INFO, "OK: link type is: %d\n", device.link_type); 

  if (device.link_type != DLT_EN10MB) {
    list = plugins_list;
    while (list) {
      if ((list->cfg.what_to_count & COUNT_SRC_MAC) || (list->cfg.what_to_count & COUNT_DST_MAC)) {
        Log(LOG_ERR, "ERROR: MAC aggregation methods not available for this link type: %d\n", device.link_type);
        exit(1);
      }
      list = list->next;
    }
  }
  
  /* doing pcap stuff */
  if (pcap_lookupnet(config.dev, &localnet, &netmask, errbuf) < 0) {
    localnet = 0;
    netmask = 0;
    Log(LOG_WARNING, "WARN: %s\n", errbuf);
  }

  if (pcap_compile(device.dev_desc, &filter, config.clbuf, 0, netmask) < 0)
    Log(LOG_WARNING, "WARN: %s\nWARN: going on without a filter\n", pcap_geterr(device.dev_desc));
  else {
    if (pcap_setfilter(device.dev_desc, &filter) < 0)
      Log(LOG_WARNING, "WARN: %s\nWARN: going on without a filter\n", pcap_geterr(device.dev_desc));
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* plugins glue: creation */
  load_plugins(&device);
  evaluate_packet_handlers();

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  if (!config.daemon) signal(SIGINT, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for(;;) {
    if (!device.active) {
      Log(LOG_WARNING, "WARN: %s become unavailable; throttling ...\n", config.dev);
      sleep(5); /* XXX: to get fixed */
      if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL) {
        Log(LOG_ERR, "ERROR: pcap_open_live(): %s\n", errbuf);
        exit(1);
      }
      pcap_setfilter(device.dev_desc, &filter);
      device.active = TRUE;
    }
    pcap_loop(device.dev_desc, -1, pcap_cb, (u_char *) &device);
    pcap_close(device.dev_desc);
    device.active = FALSE;
  }

  return 0;
}

void pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct packet_ptrs pptrs;
  struct pcap_device *device = (struct pcap_device *) user;

  /* We process the packet with the appropriate
     data link layer function */
  if (buf) { 
    pptrs.pkthdr = pkthdr;
    pptrs.packet_ptr = (u_char *) buf;
    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if (ip_handler(&pptrs)) exec_plugins(&pptrs);
    }
  }
} 

int ip_handler(register struct packet_ptrs *pptrs)
{
  register u_int8_t len = 0;
  register u_int8_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  register unsigned char *ptr;
  
  /* len: number of 32bit words forming the header */
  len = IP_HL(((struct my_iphdr *) pptrs->iph_ptr));
  len <<= 2;
  ptr = pptrs->iph_ptr+len;

  /* check len */
  if (ptr > (pptrs->packet_ptr+caplen)) return FALSE; /* IP packet truncated */
  if (len < 20) return FALSE; /* 20=sizeof(struct my_iphdr) */
  
  /* check fragments if needed */
  if (config.handle_fragments) {
    if ((ptr+sizeof(struct my_tlhdr)) > (pptrs->packet_ptr+caplen)) return FALSE; /* XXX: or TRUE ? */ 
    else pptrs->tlh_ptr = ptr; 
    
    if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_MF|IP_OFFMASK))
      return ip_fragment_handler(pptrs);
    else return TRUE;
  }
  else return TRUE;
}

void compute_once()
{
  NBO_One = htonl(1);
  PdataSz = sizeof(struct pkt_data);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
}
