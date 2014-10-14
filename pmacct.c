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


/* include */
#include "pmacct.h"
#include "pmacct-data.h"
#include "imt_plugin.h"

#define CHECK_Q_TYPE(x) x & WANT_RESET ? x ^ WANT_RESET : x

/* prototypes */
int Recv(int, unsigned char **);

/* functions */
void usage_client(char *prog)
{
  printf("%s\n", PMACCT_USAGE_HEADER);
  printf("Usage: %s [query]\n\n", prog);
  printf("Queries:\n");
  printf("  -s\tcollect full table statistics\n"); 
  printf("  -m\t[matching data] \n\tget stats with exact match; MRTG format output\n");
  printf("  -M\t[matching data] \n\tget stats with either exact or partial match; list output\n");
  printf("  -c\t[src_mac|dst_mac|vlan|src_host|dst_host|sum|src_port|dst_port|proto] \n\tspecify traffic aggregation parameter\n\t(applies to either -m or -M)\n");
  printf("  -a\tdisplay all fields\n");
  printf("  -e\tclear statistics\n");
  printf("  -r\treset counters for the specified entry \n\t(applies to either -m or -M and only to exact matches)\n");
  printf("  -t\tcheck memory table status\n");
  printf("  -p\t[file] \n\tuse the specified pipe to communicate with daemon\n");
  printf("\n");
  printf("  See EXAMPLES file in the distribution for examples\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

void print_ex_options_error()
{
  printf("ERROR: '-s', '-t', '-m', '-e' and '-M' options are each mutually exclusive.\n\n");
  exit(1);
}

void write_stats_header(unsigned long int what_to_count)
{
  if (!what_to_count) {
    printf("ID     ");
    printf("SRC MAC            ");
    printf("DST MAC            ");
    printf("VLAN   ");
    printf("SRC IP           ");
    printf("DST IP           ");
    printf("SRC PORT  ");
    printf("DST PORT  ");
    printf("PROTOCOL    ");
    printf("PACKETS     ");
    printf("BYTES\n");
  }
  else {
    if (what_to_count & COUNT_ID) printf("ID     ");
    if (what_to_count & COUNT_SRC_MAC) printf("SRC MAC            "); 
    if (what_to_count & COUNT_DST_MAC) printf("DST MAC            "); 
    if (what_to_count & COUNT_VLAN) printf("VLAN   ");
    if (what_to_count & COUNT_SRC_HOST) printf("SRC IP           ");
    if (what_to_count & COUNT_DST_HOST) printf("DST IP           ");
    if (what_to_count & COUNT_SRC_PORT) printf("SRC PORT  ");
    if (what_to_count & COUNT_DST_PORT) printf("DST PORT  "); 
    if (what_to_count & COUNT_IP_PROTO) printf("PROTOCOL    ");
    printf("PACKETS     ");
    printf("BYTES\n");
  }
}

void write_status_header()
{
  printf("* = element\n\n"); 
  printf("BUCKET\tCHAIN STATUS\n");
}

int build_query_client(char *path_ptr)
{
  struct sockaddr_un cAddr;
  int sd, rc, cLen;

  sd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sd < 0) {
    printf("ERROR: Unable to open socket.\n");
    exit(1);
  }

  cAddr.sun_family = AF_UNIX;
  strcpy(cAddr.sun_path, path_ptr);
  cLen = sizeof(cAddr);

  rc = connect(sd, (struct sockaddr *) &cAddr, cLen);
  if (rc < 0) {
    if (errno == ECONNREFUSED) {
      printf("INFO: Connection refused while trying to connect to '%s'\n\n", path_ptr);
      exit(0);
    }
    else {
      printf("ERROR: Unable to connect to '%s'\n\n", path_ptr);
      exit(1);
    }
  }

  return sd;
}

int main(int argc,char **argv)
{
  struct acc *acc_elem;
  struct bucket_desc *bd;
  struct query_header q; 
  struct pkt_primitives empty_addr, addr;
  char clibuf[LARGEBUFLEN], *bufptr;
  unsigned char *largebuf, *elem;
  char *src_ip;
  char path[128], password[9];
  int sd, num, buflen, unpacked, printed;
  int counter=0;

  /* mrtg stuff */
  char match_string[128], *match_string_token, *match_string_ptr;
  char count[128], *count_token[N_PRIMITIVES], *count_ptr;
  int count_index = 0, match_string_index = 0, index = 0;
  
  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp, want_stats, want_erase, want_reset; 
  int want_status, want_mrtg, want_match, want_all_fields;
  unsigned long int what_to_count=0;

  /* Administrativia */
  memset(clibuf, 0, LARGEBUFLEN);
  memset(&q, 0, sizeof(struct query_header));
  memset(&empty_addr, 0, sizeof(struct pkt_primitives));
  memset(count, 0, sizeof(count));
  memset(&addr, 0, sizeof(struct pkt_primitives));
  memset(password, 0, sizeof(password)); 

  strcpy(path, "/tmp/collect.pipe");
  unpacked = 0; printed = 0;
  errflag = 0; buflen = 0;
  want_stats = FALSE;
  want_erase = FALSE;
  want_status = FALSE;
  want_mrtg = FALSE;
  want_match = FALSE;
  want_all_fields = FALSE;
  want_reset = FALSE;

  bufptr = clibuf; 
  bufptr += sizeof(struct query_header);

  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCT)) != -1)) {
    switch (cp) {
    case 's':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATS;
      want_stats = TRUE;
      break;
    case 'c':
      strlcpy(count, optarg, sizeof(count));
      count_ptr = count;
      while ((*count_ptr != '\0') && (count_index <= N_PRIMITIVES-1)) {
        count_token[count_index] = extract_token(&count_ptr, ',');
	if (!strcmp(count_token[count_index], "src_host")) what_to_count |= COUNT_SRC_HOST;
        else if (!strcmp(count_token[count_index], "dst_host")) what_to_count |= COUNT_DST_HOST;
        else if (!strcmp(count_token[count_index], "sum")) what_to_count |= COUNT_SUM_HOST;
        else if (!strcmp(count_token[count_index], "src_port")) what_to_count |= COUNT_SRC_PORT;
        else if (!strcmp(count_token[count_index], "dst_port")) what_to_count |= COUNT_DST_PORT;
        else if (!strcmp(count_token[count_index], "proto")) what_to_count |= COUNT_IP_PROTO;
        else if (!strcmp(count_token[count_index], "src_mac")) what_to_count |= COUNT_SRC_MAC;
        else if (!strcmp(count_token[count_index], "dst_mac")) what_to_count |= COUNT_DST_MAC;
        else if (!strcmp(count_token[count_index], "vlan")) what_to_count |= COUNT_VLAN;
        else printf("WARN: ignoring unknown aggregation method: %s.\n", count_token[count_index]);
	count_index++;
      }
      q.what_to_count = what_to_count;
      break;
    case 'e':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_ERASE; 
      want_erase = TRUE;
      break;
    case 't':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATUS; 
      want_status = TRUE;
      break;
    case 'm':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      q.type |= WANT_MRTG; 
      want_mrtg = TRUE;
      break;
    case 'M':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      q.type |= WANT_MATCH;
      want_match = TRUE;
      break;
    case 'p':
      strlcpy(path, optarg, sizeof(path));
      break;
    case 'P':
      strlcpy(password, optarg, sizeof(password));
      break;
    case 'a':
      want_all_fields = TRUE;
      break;
    case 'r':
      q.type |= WANT_RESET;
      want_reset = TRUE;
      break;
    default:
      printf("ERROR: parameter %c unknown! \n  Exiting...\n\n", cp);
      usage_client(argv[0]);
      exit(1);
      break;
    } 
  }

  /* some post-getopt-processing task */
  if (!q.type) {
    printf("ERROR: no -s, -e, -t or -m option specified. \n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if ((want_mrtg || want_match) && !what_to_count) {
    printf("ERROR: '-m' or '-M' selected but '-c' has not been specified or is invalid.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (want_reset && !(want_mrtg || want_match)) {
    printf("ERROR: '-r' selected but either '-m' or '-M' has not been specified.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  memcpy(q.passwd, password, sizeof(password));
  
  if (want_mrtg || want_match) {
    match_string_ptr = match_string;
    while ((*match_string_ptr != '\0') && (match_string_index < count_index))  {
      match_string_token = extract_token(&match_string_ptr, ',');
      if (!strcmp(count_token[match_string_index], "src_host")) {
	if (!inet_aton(match_string_token, &addr.src_ip)) {
	  printf("ERROR: src_host: Invalid IP address\n");
	  exit(1);
	}
      }
      else if (!strcmp(count_token[match_string_index], "dst_host")) {
        if (!inet_aton(match_string_token, &addr.dst_ip)) {
          printf("ERROR: dst_host: Invalid IP address\n");
          exit(1);
        }
      }
      else if (!strcmp(count_token[match_string_index], "src_mac")) {
        unsigned char *eth_ptr;

        eth_ptr = (unsigned char *)ether_aton(match_string_token);
	if (!eth_ptr) {
	  printf("ERROR: src_mac: Invalid MAC address\n");
          exit(1);
	}
	else memcpy(&addr.eth_shost, eth_ptr, ETH_ADDR_LEN);
      }
      else if (!strcmp(count_token[match_string_index], "dst_mac")) {
        unsigned char *eth_ptr;

        eth_ptr = (unsigned char *)ether_aton(match_string_token);
        if (!eth_ptr) {
          printf("ERROR: src_mac: Invalid MAC address\n");
          exit(1);
        }
        else memcpy(&addr.eth_dhost, eth_ptr, ETH_ADDR_LEN);
      }
      else if (!strcmp(count_token[match_string_index], "vlan")) {
	addr.vlan_id = atoi(match_string_token);
      }
      else if (!strcmp(count_token[match_string_index], "src_port")) { 
        addr.src_port = atoi(match_string_token);
      }
      else if (!strcmp(count_token[match_string_index], "dst_port")) {
        addr.dst_port = atoi(match_string_token);
      }
      else if (!strcmp(count_token[match_string_index], "proto")) {
	while (_protocols[index].number != -1) { 
	  if (!strcmp(_protocols[index].name, match_string_token)) {
	    addr.proto = _protocols[index].number;
	    break;
	  }
	  index++;
	}
	if (addr.proto <= 0) {
	  addr.proto = atoi(match_string_token);
	  if ((addr.proto <= 0) || (addr.proto > 255)) {
	    printf("ERROR: invalid protocol, %s\n", match_string_token);
	    exit(1);
	  }
	}
      }
      else printf("WARN: ignoring unknown aggregation method: %s.\n", *count_token);
      match_string_index++;
    }

    memcpy(bufptr, &addr, sizeof(struct pkt_primitives));
  }

  /* arranging header and size of buffer to send */
  memcpy(clibuf, &q, sizeof(struct query_header)); 
  buflen = sizeof(struct query_header)+sizeof(struct pkt_primitives);
  
  sd = build_query_client(path);
  send(sd, clibuf, buflen, 0);
  if (want_stats || want_match) {
    unpacked = Recv(sd, &largebuf);
    if (want_all_fields) what_to_count = FALSE; 
    else what_to_count = ((struct query_header *)largebuf)->what_to_count;
    write_stats_header(what_to_count);
    elem = largebuf+sizeof(struct query_header);
    unpacked -= sizeof(struct query_header);
    while (printed < unpacked) {
      acc_elem = (struct acc *) elem;
      if (memcmp(&acc_elem, &empty_addr, sizeof(struct pkt_primitives)) != 0) {
        if ((!what_to_count) || (what_to_count & COUNT_ID))
	  printf("%-5d  ", acc_elem->id);

	if ((!what_to_count) || (what_to_count & COUNT_SRC_MAC)) {
	  src_ip = (char *) ether_ntoa(acc_elem->eth_shost);
	  printf("%-17s  ", src_ip);
	}

	if ((!what_to_count) || (what_to_count & COUNT_DST_MAC)) {
	  src_ip = (char *) ether_ntoa(acc_elem->eth_dhost);
	  printf("%-17s  ", src_ip);
	} 

	if ((!what_to_count) || (what_to_count & COUNT_VLAN)) {
          printf("%-5d  ", acc_elem->vlan_id);
        }

	if ((!what_to_count) || (what_to_count & COUNT_SRC_HOST)
	  || (what_to_count & COUNT_SUM_HOST)) {
          src_ip = inet_ntoa(acc_elem->src_ip);
	  printf("%-15s  ", src_ip);
	}
	
	if ((!what_to_count) || (what_to_count & COUNT_DST_HOST)) {
	  src_ip = inet_ntoa(acc_elem->dst_ip);
	  printf("%-15s  ", src_ip);
	}

	if ((!what_to_count) || (what_to_count & COUNT_SRC_PORT))
	  printf("%-5d     ", acc_elem->src_port);

	if ((!what_to_count) || (what_to_count & COUNT_DST_PORT))
	  printf("%-5d     ", acc_elem->dst_port);

	if ((!what_to_count) || (what_to_count & COUNT_IP_PROTO))
	  printf("%-10s  ", _protocols[acc_elem->proto].name);

        printf("%-10u  ", acc_elem->packet_counter); 
        printf("%u\n", acc_elem->bytes_counter); 
        counter++;
      }
      elem += sizeof(struct acc);
      printed += sizeof(struct acc);
    }
    printf("\nFor a total of: %d entries\n", counter);
  }
  else if (want_erase) printf("OK: Clearing stats.\n");
  else if (want_status) {
    unpacked = Recv(sd, &largebuf);
    write_status_header();
    elem = largebuf+sizeof(struct query_header);
    unpacked -= sizeof(struct query_header);
    while (printed < unpacked) {
      bd = (struct bucket_desc *) elem;
      printf("%u\t", bd->num);
      while (bd->howmany > 0) {
        printf("*");
	bd->howmany--;
      }
      printf("\n");

      elem += sizeof(struct bucket_desc);
      printed += sizeof(struct bucket_desc);
    }
  }
  else if (want_mrtg) {
    char *base;

    memset(clibuf, 0, LARGEBUFLEN);
    num = recv(sd, clibuf, LARGEBUFLEN, 0);
    base = clibuf+sizeof(struct query_header);
    acc_elem = (struct acc *) base;
    if (memcmp(&acc_elem, &empty_addr, sizeof(struct pkt_primitives)) != 0) {
      printf("0\n"); /* input bytes */
      printf("%d\n", acc_elem->bytes_counter); /* output bytes */
      printf("0\n"); /* uptime */
      printf("0\n"); /* description */
    }
    else printf("INFO: Any entry matching your request has been found\n"); 
  }
  else {
    usage_client(argv[0]);
    exit(1);
  }

  close(sd);

  return 0;
}

char *extract_token(char **string, int delim)
{
  char *token, *delim_ptr;

  if ((delim_ptr = strchr(*string, delim))) {
    *delim_ptr = '\0';
    token = *string;
    *string = delim_ptr+1;
  }
  else {
    token = *string;
    *string += strlen(*string);
  }

  return token;
}

int Recv(int sd, unsigned char **buf) 
{
  int num, unpacked = 0, round = 0; 
  unsigned char rxbuf[LARGEBUFLEN], *elem;

  *buf = (unsigned char *) malloc(LARGEBUFLEN);
  memset(*buf, 0, LARGEBUFLEN);
  memset(rxbuf, 0, LARGEBUFLEN);

  do {
    num = recv(sd, rxbuf, LARGEBUFLEN, 0);
    if (num > 0) {
      /* check 1: enough space in allocated buffer */
      if (unpacked+num >= round*LARGEBUFLEN) {
        round++;
        *buf = realloc((unsigned char *) *buf, round*LARGEBUFLEN);
        if (!(*buf)) {
          printf("ERROR: realloc() out of memory\n");
          exit(1);
        }
        /* ensuring realloc() didn't move somewhere else our memory area */
        elem = *buf;
        elem += unpacked;
      }
      /* check 2: enough space in dss */
      if (((u_int32_t)elem+num) > (u_int32_t)sbrk(0)) sbrk(LARGEBUFLEN);

      memcpy(elem, rxbuf, num);
      unpacked += num;
      elem += num;
    }
  } while (num > 0);

  return unpacked;
}
