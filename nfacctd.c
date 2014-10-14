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
#define __NFACCTD_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "nf_map_handlers.h"
#include "nfacctd-data.h"
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
  printf("Usage: %s [-D] [-l port ] [-P plugin] [plugin options]\n", prog_name);
  printf("       %s [-f config_file]\n", prog_name);
  printf("       %s [-h]\n", prog_name);
  printf("\n-GENERAL- options:\n");
  printf("  -l  \tlisten to the specified UDP port\n");
  printf("  -f  \tspecify a configuration file (see CONFIG-KEYS file for the valid config keys list)\n");
  printf("  -c  \t[src_host|dst_host|src_net|dst_net|sum|src_port|dst_port|proto] \n\tcounts source, destination or total IP traffic\n");
  printf("  -D  \tdaemonize the process\n"); 
  printf("  -n  \tpath for the file containing network definitions (when using 'src_net' or 'dst_net')\n");
  printf("  -P  \t[memory|print|mysql|pgsql] \n\tactivate specified plugins\n"); 
  printf("  -d  \tenables debug mode\n");
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
  struct sockaddr_in server, client;
  struct packet_ptrs pptrs;
  char config_file[SRVBUFLEN];
  unsigned char netflow_packet[NETFLOW_MSG_SIZE];
  int ret, index, logf, sd, rc, clen = sizeof(client), yes=1, allowed;
  struct hosts_table allow;
  struct id_table idt;

  /* dummy stuff */
  struct pcap_device device;
  unsigned char dummy_packet[38]; /* eth_header+my_iphdr+my_tlhdr */
  struct pcap_pkthdr dummy_pkthdr;

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
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
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
    if (list->cfg.pre_tag_map || list->cfg.post_tag) list->cfg.what_to_count |= COUNT_ID; /* sanity checks will follow later */
    if (strcmp(list->type.string, "core")) {  
      if ((list->cfg.what_to_count & COUNT_SRC_MAC) || (list->cfg.what_to_count & COUNT_DST_MAC) ||
        (list->cfg.what_to_count & COUNT_VLAN)) {
        printf("ERROR: 'src_mac', 'dst_mac' and 'vlan' aggregations are not supported into nfacctd.\n");
        exit(1);
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

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* socket creation */
  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    Log(LOG_ERR, "ERROR: socket() failed.\n");
    exit(1);
  }

  /* bind socket to port */
  server.sin_family = AF_INET;
  if (config.nfacctd_ip) {
    struct in_addr a;

    if (inet_aton(config.nfacctd_ip, &a)) server.sin_addr.s_addr = a.s_addr;
    else {
      Log(LOG_ERR, "ERROR: 'nfacctd_ip' value is not valid. Exiting.\n");
      exit(1);
    }
  }
  else server.sin_addr.s_addr = htonl(INADDR_ANY);
  if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
  server.sin_port = htons(config.nfacctd_port);

  rc = Setsocksize(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN: Setsocksize() failed for SO_REUSEADDR.\n");

  if (config.pipe_size) {
    rc = Setsocksize(sd, SOL_SOCKET, SO_RCVBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_ERR, "WARN: Setsocksize() failed for 'plugin_pipe_size' = '%d'.\n", config.pipe_size); 
  }

  rc = bind(sd, (struct sockaddr *) &server, sizeof(server));
  if (rc < 0) {
    Log(LOG_ERR, "ERROR: bind() to port '%d' failed.\n", config.nfacctd_port);
    exit(1);
  }

  if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);
  else memset(&allow, 0, sizeof(allow));

  if (config.pre_tag_map) {
    load_id_file(config.pre_tag_map, &idt);
    pptrs.idtable = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    pptrs.idtable = NULL;
  }

  /* plugins glue: creation */
  memset(&device, 0, sizeof(struct pcap_device));
  device.dev_desc = pcap_open_dead(1, 38); /* link=1,snaplen=eth_header+my_iphdr+my_tlhdr */
  load_plugins(&device);
  pcap_close(device.dev_desc);
  evaluate_packet_handlers();

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  if (!config.daemon) signal(SIGINT, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* arranging misc static pointers */ 
  pptrs.f_agent = (u_char *) &client;

  /* arranging static pointers to dummy packet */
  memset(dummy_packet, 0, sizeof(dummy_packet));

  pptrs.packet_ptr = dummy_packet;
  pptrs.pkthdr = &dummy_pkthdr;
  ((struct eth_header *)pptrs.packet_ptr)->ether_type = htons(ETHERTYPE_IP); /* 0x800 */
  pptrs.iph_ptr = pptrs.packet_ptr + ETHER_HDRLEN; 
  pptrs.tlh_ptr = pptrs.packet_ptr + ETHER_HDRLEN + sizeof(struct my_iphdr); 
  pptrs.pkthdr->caplen = 38; /* eth_header + my_iphdr + my_tlhdr */
  pptrs.pkthdr->len = 100; /* fake len */ 
  ((struct my_iphdr *)pptrs.iph_ptr)->ip_vhl = 5;

  if (config.debug) Log(LOG_DEBUG, "DEBUG: waiting for data on UDP port '%u'\n", config.nfacctd_port);

  /* Main loop */
  for(;;) {
    allowed = FALSE;
    memset(netflow_packet, 0, NETFLOW_MSG_SIZE);
    ret = recvfrom(sd, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);

    /* hosts allow table is not loaded */
    if (!allow.num) allowed = TRUE;
    else {
      for (index = 0; index < allow.num; index++) {
        /* enforcing hosts allow table rules */
        if (client.sin_addr.s_addr == allow.table[index].s_addr) allowed = TRUE;
      }
    }

    if (allowed) {
      switch(ntohs(((struct struct_header_v5 *)netflow_packet)->version)) {
      case 1:
        process_v1_packet(netflow_packet, &pptrs);
        break;
      case 5:
        process_v5_packet(netflow_packet, &pptrs); 
        break;
      default:
        break;
      } 
    }
  }

  return 0;
}

void process_v1_packet(unsigned char *pkt, struct packet_ptrs *pptrs)
{
  struct struct_header_v1 *hdr_v1 = (struct struct_header_v1 *)pkt;
  struct struct_export_v1 *exp_v1;
  unsigned short int count = ntohs(hdr_v1->count);

  pptrs->f_header = pkt;
  pkt += NfHdrV1Sz; 
  exp_v1 = (struct struct_export_v1 *)pkt;

  if (count <= V1_MAXFLOWS) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v1;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr = exp_v1->srcaddr.s_addr;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr = exp_v1->dstaddr.s_addr;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_p = exp_v1->prot;
      ((struct my_tlhdr *)pptrs->tlh_ptr)->src_port = exp_v1->srcport;
      ((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port = exp_v1->dstport;

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) ((struct my_iphdr *)pptrs->iph_ptr)->ip_id = find_id(pptrs);
      exec_plugins(pptrs);
      exp_v1++;           
      count--;             
    }
  }
}

void process_v5_packet(unsigned char *pkt, struct packet_ptrs *pptrs)
{
  struct struct_header_v5 *hdr_v5 = (struct struct_header_v5 *)pkt;
  struct struct_export_v5 *exp_v5;
  unsigned short int count = ntohs(hdr_v5->count);
  int id;

  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;

  if (count <= V5_MAXFLOWS) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v5;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr = exp_v5->srcaddr.s_addr;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr = exp_v5->dstaddr.s_addr;
      ((struct my_iphdr *)pptrs->iph_ptr)->ip_p = exp_v5->prot;
      ((struct my_tlhdr *)pptrs->tlh_ptr)->src_port = exp_v5->srcport;
      ((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port = exp_v5->dstport;

      /* IP header's id field is unused; we will use it to transport our id */ 
      if (config.pre_tag_map) ((struct my_iphdr *)pptrs->iph_ptr)->ip_id = find_id(pptrs);
      exec_plugins(pptrs);
      exp_v5++;
      count--;
    }
  }
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
	  if (inet_aton(buf, &t->table[index])) index++;
	  else Log(LOG_WARNING, "WARN: 'nfacctd_allow_file': Bad IP address '%s'. Ignored.\n", buf);
        }
      }
    }
    t->num = index;
  }
}

int find_id(struct packet_ptrs *pptrs)
{
  struct id_table *t = (struct id_table *)pptrs->idtable;
  int x, j, id, stop;

  id = 0;
  for (x = 0; x < t->num; x++) {
    if (t->e[x].agent_ip.s_addr == ((struct sockaddr_in *)pptrs->f_agent)->sin_addr.s_addr) {
      for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
      if (id) break;
    }
    else if (t->e[x].agent_ip.s_addr > ((struct sockaddr_in *)pptrs->f_agent)->sin_addr.s_addr) break;
  }

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
}
