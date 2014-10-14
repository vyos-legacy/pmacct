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

#define __PMACCT_CLIENT_C

/* include */
#include "pmacct.h"
#include "pmacct-data.h"
#include "imt_plugin.h"

/* prototypes */
int Recv(int, unsigned char **);
int sanitize_buf(char *);
void trim_all_spaces(char *);
void print_ex_options_error();
void write_status_header();
char *extract_token(char **, int);
int CHECK_Q_TYPE(int);

/* functions */
int CHECK_Q_TYPE(int type)
{
  if (!type) return 0;

  if (type & WANT_RESET) type ^= WANT_RESET;
  if (type & WANT_ERASE) type ^= WANT_ERASE;

  return type;
}

void usage_client(char *prog)
{
  printf("%s\n", PMACCT_USAGE_HEADER);
  printf("Usage: %s [query]\n\n", prog);
  printf("Queries:\n");
  printf("  -s\tcollect full table statistics\n"); 
  printf("  -N\t[matching data[';' ... ]] | ['file:'[filename]] \n\tmatch actual data; print counter(s) only\n");
  printf("  -n\t[bytes|packets|flows|all] \n\tselect counter to print (applies to -N)\n");
  printf("  -S\tSum counters instead of returning a single counter for each request (applies to -N)\n");
  printf("  -M\t[matching data[';' ... ]] | ['file:'[filename]] \n\tmatch actual data; print formatted table\n");
  printf("  -a\tdisplay all table fields (even those currently unused)\n");
  printf("  -c\t[src_mac|dst_mac|vlan|src_host|dst_host|src_port|dst_port|tos|proto|src_as|dst_as| \n\t |sum_mac|sum_host|sum_net|sum_as|sum_port|tag|flows] \n\tselect primitives and flows (required by -N and -M)\n");
  printf("  -e\tclear statistics\n");
  printf("  -r\treset counters for the matched entries (applies to either -N or -M)\n");
  printf("  -t\tcheck table status\n");
  printf("  -p\t[file] \n\tsocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("\n");
  printf("  See EXAMPLES file in the distribution for examples\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

int sanitize_buf(char *buf)
{
  int x = 0, valid_char = 0;

  trim_all_spaces(buf);
  while (x < strlen(buf)) {
    if (!isspace(buf[x])) valid_char++;
    x++;
  }
  if (!valid_char) return TRUE;
  if (buf[0] == '!') return TRUE;

  return FALSE;
}

void trim_all_spaces(char *buf)
{
  char *ptr;
  int i = 0, len;

  ptr = buf;
  len = strlen(buf);

  /* trimming all spaces */
  while (i <= len) {
    if (isspace(ptr[i])) {
      strcpy(&buf[i], &ptr[i+1]);
      len--;
    }
    else i++;
  }
}

void print_ex_options_error()
{
  printf("ERROR: '-s', '-t', '-N', and '-M' options are each mutually exclusive.\n\n");
  exit(1);
}

void write_stats_header(u_int32_t what_to_count, u_int8_t have_wtc)
{
  if (!have_wtc) {
    printf("ID     ");
    printf("SRC MAC            ");
    printf("DST MAC            ");
    printf("VLAN   ");
#if defined ENABLE_IPV6
    printf("SRC IP                                         ");
    printf("DST IP                                         ");
#else
    printf("SRC IP           ");
    printf("DST IP           ");
#endif
    printf("SRC PORT  ");
    printf("DST PORT  ");
    printf("PROTOCOL    ");
    printf("TOS    ");
    printf("PACKETS     ");
    printf("FLOWS       ");
    printf("BYTES\n");
  }
  else {
    if (what_to_count & COUNT_ID) printf("ID     ");
#if defined HAVE_L2
    if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) printf("SRC MAC            "); 
    if (what_to_count & COUNT_DST_MAC) printf("DST MAC            "); 
    if (what_to_count & COUNT_VLAN) printf("VLAN   ");
#endif
#if defined ENABLE_IPV6
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SRC_AS)) printf("SRC IP                                         "); 
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET|COUNT_SUM_AS)) printf("SRC IP                                         ");
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_DST_AS)) printf("DST IP                                         ");
#else
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SRC_AS)) printf("SRC IP           ");
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET|COUNT_SUM_AS)) printf("SRC IP           ");
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_DST_AS)) printf("DST IP           ");
#endif
    if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) printf("SRC PORT  ");
    if (what_to_count & COUNT_DST_PORT) printf("DST PORT  "); 
    if (what_to_count & COUNT_IP_PROTO) printf("PROTOCOL    ");
    if (what_to_count & COUNT_IP_TOS) printf("TOS    ");
    printf("PACKETS     ");
    if (what_to_count & COUNT_FLOWS) printf("FLOWS       ");
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
  int clibufsz = (MAX_QUERIES*sizeof(struct query_entry))+sizeof(struct query_header)+2;
  struct pkt_data *acc_elem;
  struct bucket_desc *bd;
  struct query_header q; 
  struct pkt_primitives empty_addr;
  struct query_entry request;
  char clibuf[clibufsz], *bufptr;
  unsigned char *largebuf, *elem;
  char ethernet_address[17], ip_address[INET6_ADDRSTRLEN];
  char path[128], file[128], password[9];
  int sd, buflen, unpacked, printed;
  int counter=0;

  /* mrtg stuff */
  char match_string[LARGEBUFLEN], *match_string_token, *match_string_ptr;
  char count[128], *count_token[N_PRIMITIVES], *count_ptr;
  int count_index = 0, match_string_index = 0, index = 0;
  u_int32_t count_token_int[N_PRIMITIVES];
  
  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp, want_stats, want_erase, want_reset; 
  int want_status, want_mrtg, want_counter, want_match, want_all_fields;
  int which_counter, fetch_from_file, sum_counters;
  u_int32_t what_to_count, have_wtc, tmpnum;

  /* Administrativia */
  memset(&q, 0, sizeof(struct query_header));
  memset(&empty_addr, 0, sizeof(struct pkt_primitives));
  memset(count, 0, sizeof(count));
  memset(password, 0, sizeof(password)); 

  strcpy(path, "/tmp/collect.pipe");
  unpacked = 0; printed = 0;
  errflag = 0; buflen = 0;
  want_stats = FALSE;
  want_erase = FALSE;
  want_status = FALSE;
  want_counter = FALSE;
  want_mrtg = FALSE;
  want_match = FALSE;
  want_all_fields = FALSE;
  want_reset = FALSE;
  which_counter = FALSE;
  sum_counters = FALSE;
  fetch_from_file = FALSE;
  what_to_count = FALSE;
  have_wtc = FALSE;

  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCT)) != -1)) {
    switch (cp) {
    case 's':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATS;
      q.num = 1;
      want_stats = TRUE;
      break;
    case 'c':
      strlcpy(count, optarg, sizeof(count));
      count_ptr = count;
      while ((*count_ptr != '\0') && (count_index <= N_PRIMITIVES-1)) {
        count_token[count_index] = extract_token(&count_ptr, ',');
	if (!strcmp(count_token[count_index], "src_host")) {
	  count_token_int[count_index] = COUNT_SRC_HOST;
	  what_to_count |= COUNT_SRC_HOST;
	}
        else if (!strcmp(count_token[count_index], "dst_host")) {
	  count_token_int[count_index] = COUNT_DST_HOST;
	  what_to_count |= COUNT_DST_HOST;
	}
        else if (!strcmp(count_token[count_index], "sum")) {
	  count_token_int[count_index] = COUNT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "src_port")) {
	  count_token_int[count_index] = COUNT_SRC_PORT;
	  what_to_count |= COUNT_SRC_PORT;
	}
        else if (!strcmp(count_token[count_index], "dst_port")) {
	  count_token_int[count_index] = COUNT_DST_PORT;
	  what_to_count |= COUNT_DST_PORT;
	}
        else if (!strcmp(count_token[count_index], "proto")) {
	  count_token_int[count_index] = COUNT_IP_PROTO;
	  what_to_count |= COUNT_IP_PROTO;
	}
#if defined HAVE_L2
        else if (!strcmp(count_token[count_index], "src_mac")) {
	  count_token_int[count_index] = COUNT_SRC_MAC;
	  what_to_count |= COUNT_SRC_MAC;
	}
        else if (!strcmp(count_token[count_index], "dst_mac")) {
	  count_token_int[count_index] = COUNT_DST_MAC;
	  what_to_count |= COUNT_DST_MAC;
	}
        else if (!strcmp(count_token[count_index], "vlan")) {
	  count_token_int[count_index] = COUNT_VLAN;
	  what_to_count |= COUNT_VLAN;
	}
	else if (!strcmp(count_token[count_index], "sum_mac")) {
	  count_token_int[count_index] = COUNT_SUM_MAC;
	  what_to_count |= COUNT_SUM_MAC;
	}
#endif 
        else if (!strcmp(count_token[count_index], "tos")) {
	  count_token_int[count_index] = COUNT_IP_TOS;
	  what_to_count |= COUNT_IP_TOS;
	}
        else if (!strcmp(count_token[count_index], "none")) {
	  count_token_int[count_index] = COUNT_NONE;
	  what_to_count |= COUNT_NONE;
	}
        else if (!strcmp(count_token[count_index], "src_as")) {
	  count_token_int[count_index] = COUNT_SRC_AS;
	  what_to_count |= COUNT_SRC_AS;
	}
        else if (!strcmp(count_token[count_index], "dst_as")) {
	  count_token_int[count_index] = COUNT_DST_AS;
	  what_to_count |= COUNT_DST_AS;
	}
        else if (!strcmp(count_token[count_index], "src_net")) {
	  count_token_int[count_index] = COUNT_SRC_NET;
	  what_to_count |= COUNT_SRC_NET;
	}
        else if (!strcmp(count_token[count_index], "dst_net")) {
	  count_token_int[count_index] = COUNT_DST_NET;
	  what_to_count |= COUNT_DST_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_host")) {
	  count_token_int[count_index] = COUNT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "sum_net")) {
	  count_token_int[count_index] = COUNT_SUM_NET;
	  what_to_count |= COUNT_SUM_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_as")) {
	  count_token_int[count_index] = COUNT_SUM_AS;
	  what_to_count |= COUNT_SUM_AS;
	}
        else if (!strcmp(count_token[count_index], "sum_port")) {
	  count_token_int[count_index] = COUNT_SUM_PORT;
	  what_to_count |= COUNT_SUM_PORT;
	}
        else if (!strcmp(count_token[count_index], "tag")) {
	  count_token_int[count_index] = COUNT_ID;
	  what_to_count |= COUNT_ID;
	}
        else printf("WARN: ignoring unknown aggregation method: %s.\n", count_token[count_index]);
	count_index++;
      }
      break;
    case 'e':
      q.type |= WANT_ERASE; 
      want_erase = TRUE;
      break;
    case 't':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATUS; 
      want_status = TRUE;
      break;
    case 'm': /* obsoleted */
      want_mrtg = TRUE;
    case 'N':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      match_string[LARGEBUFLEN-1] = '\0';
      q.type |= WANT_COUNTER; 
      want_counter = TRUE;
      break;
    case 'n':
      if (!strcmp(optarg, "bytes")) which_counter = 0;
      else if (!strcmp(optarg, "packets")) which_counter = 1;
      else if (!strcmp(optarg, "flows")) which_counter = 3;
      else if (!strcmp(optarg, "all")) which_counter = 2;
      else printf("WARN: ignoring unknown counter: %s.\n", optarg);
      break;
    case 'S':
      sum_counters = TRUE;
      break;
    case 'M':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      match_string[LARGEBUFLEN-1] = '\0';
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
    printf("ERROR: no -s, -e, -t or -N option specified. \n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if ((want_counter || want_match) && !what_to_count) {
    printf("ERROR: '-N' or '-M' selected but '-c' has not been specified or is invalid.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (want_reset && !(want_counter || want_match)) {
    printf("ERROR: '-r' selected but either '-N' or '-M' has not been specified.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if ((which_counter||sum_counters) && !want_counter) {
    printf("ERROR: '-n' and '-S' options apply only to '-N'.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (want_counter || want_match) {
    char *ptr = match_string, prefix[] = "file:";

    while(isspace(*ptr)) ptr++;
    if (!strncmp(ptr, prefix, strlen(prefix))) {
      fetch_from_file = TRUE; 
      ptr += strlen(prefix);
      strlcpy(file, ptr, sizeof(file)); 
    }
  }

  memcpy(q.passwd, password, sizeof(password));
  
  if (want_counter || want_match) {
    FILE *f;
    int strnum; 
    char **strings, *tptr1, *tptr2, tmpstr[SRVBUFLEN];
    char *tmpbuf, *tmpbufptr;
    
    /* 1st step: count how many queries we will have */
    if (!fetch_from_file) {
      for (strnum = 0, tptr1 = match_string; tptr1 && (strnum < MAX_QUERIES); strnum++) {
        tptr2 = tptr1;
        tptr1 = strchr(tptr1, ';'); 
        if (tptr1) {
	  if (*tptr2 == *tptr1) strnum--; /* void string */
	  tptr1++;
        }
      } 
    }
    else {
      if ((f = fopen(file, "r")) == NULL) {
        printf("ERROR: file '%s' not found\n", file);
        exit(1);
      }      
      else {
	strnum = 0;
	while (!feof(f) && (strnum < MAX_QUERIES)) {
	  if (fgets(tmpstr, SRVBUFLEN, f)) { 
	    if (!sanitize_buf(tmpstr)) strnum++;
	  }
	}
      }
    }

    strings = malloc((strnum+1)*sizeof(char *));
    if (!strings) {
      printf("ERROR: Unable to allocate sufficient memory.\n");
      exit(1); 
    }
    memset(strings, 0, (strnum+1)*sizeof(char *));

    if (fetch_from_file) {
      tmpbuf = malloc((strnum+1)*SRVBUFLEN);
      if (!tmpbuf) {
	printf("ERROR: Unable to allocate sufficient memory.\n");
	exit(1);
      }
      memset(tmpbuf, 0, (strnum+1)*SRVBUFLEN);
    }

    /* 2nd step: tokenize the whole string */
    if (!fetch_from_file) {
      for (strnum = 0, tptr1 = match_string; tptr1 && (strnum < MAX_QUERIES); strnum++) {
        tptr2 = tptr1;
        tptr1 = strchr(tptr1, ';');
        if (tptr1) *tptr1 = '\0';
        if (strlen(tptr2)) strings[strnum] = tptr2;
        else strnum--; /* void string */
        if (tptr1) tptr1++;
      }
    }
    else {
      freopen(file, "r", f);
      strnum = 0;
      tmpbufptr = tmpbuf;
      while (!feof(f) && (strnum < MAX_QUERIES)) {
        if (fgets(tmpbufptr, SRVBUFLEN, f)) {
	  tmpbufptr[SRVBUFLEN-1] = '\0';
	  if (!sanitize_buf(tmpbufptr)) {
	    strings[strnum] = tmpbufptr;
	    strnum++;
	    tmpbufptr += SRVBUFLEN;
	  }
        }
      }
      fclose(f);
    }

    bufptr = clibuf;
    bufptr += sizeof(struct query_header);
    
    /* 4th step: build queries */
    for (q.num = 0; (q.num < strnum) && (q.num < MAX_QUERIES); q.num++) {
      u_int32_t entry_wtc = what_to_count;

      match_string_ptr = strings[q.num];
      match_string_index = 0;
      memset(&request, 0, sizeof(struct query_entry));
      request.what_to_count = what_to_count;
      while ((*match_string_ptr != '\0') && (match_string_index < count_index))  {
        match_string_token = extract_token(&match_string_ptr, ',');

	/* Handling wildcards meaningfully */
	if (!strcmp(match_string_token, "*")) {
          request.what_to_count ^= count_token_int[match_string_index];	  
	  match_string_index++;
	  continue;
	}

        if (!strcmp(count_token[match_string_index], "src_host") ||
	    !strcmp(count_token[match_string_index], "src_net") ||
	    !strcmp(count_token[match_string_index], "sum_host") ||
	    !strcmp(count_token[match_string_index], "sum_net")) {
	  if (!str_to_addr(match_string_token, &request.data.src_ip)) {
	    printf("ERROR: src_host: Invalid IP address: '%s'\n", match_string_token);
	    exit(1);
	  }
        }
        else if (!strcmp(count_token[match_string_index], "dst_host") ||
		 !strcmp(count_token[match_string_index], "dst_net")) {
          if (!str_to_addr(match_string_token, &request.data.dst_ip)) {
            printf("ERROR: dst_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
#if defined (HAVE_L2)
        else if (!strcmp(count_token[match_string_index], "src_mac") ||
		 !strcmp(count_token[match_string_index], "sum_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
	  int res;

          res = string_etheraddr(match_string_token, ethaddr);
	  if (res) {
	    printf("ERROR: src_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
	  }
	  else memcpy(&request.data.eth_shost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "dst_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
	  int res;

          res = string_etheraddr(match_string_token, ethaddr);
          if (res) {
            printf("ERROR: src_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
          }
          else memcpy(&request.data.eth_dhost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "vlan")) {
	  request.data.vlan_id = atoi(match_string_token);
        }
#endif
        else if (!strcmp(count_token[match_string_index], "src_port") ||
		 !strcmp(count_token[match_string_index], "sum_port")) { 
          request.data.src_port = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "dst_port")) {
          request.data.dst_port = atoi(match_string_token);
        }
	else if (!strcmp(count_token[match_string_index], "tos")) {
	  tmpnum = atoi(match_string_token);
	  request.data.tos = (u_int8_t) tmpnum; 
	}
        else if (!strcmp(count_token[match_string_index], "proto")) {
	  for (index = 0; _protocols[index].number != -1; index++) { 
	    if (!strcmp(_protocols[index].name, match_string_token)) {
	      request.data.proto = _protocols[index].number;
	      break;
	    }
	  }
	  if (request.data.proto <= 0) {
	    request.data.proto = atoi(match_string_token);
	    if ((request.data.proto <= 0) || (request.data.proto > 255)) {
	      printf("ERROR: invalid protocol: '%s'\n", match_string_token);
	      exit(1);
	    }
	  }
        }
	else if (!strcmp(count_token[match_string_index], "none"));
	else if (!strcmp(count_token[match_string_index], "src_as") ||
		 !strcmp(count_token[match_string_index], "sum_as")) {
	  request.data.src_ip.family = AF_INET;
	  request.data.src_ip.address.ipv4.s_addr = atoi(match_string_token);
	  request.data.src_ip.address.ipv4.s_addr = htonl(request.data.src_ip.address.ipv4.s_addr);
	}
	else if (!strcmp(count_token[match_string_index], "dst_as")) {
	  request.data.dst_ip.family = AF_INET;
	  request.data.dst_ip.address.ipv4.s_addr = atoi(match_string_token);
	  request.data.dst_ip.address.ipv4.s_addr = htonl(request.data.dst_ip.address.ipv4.s_addr);
	}
	else if (!strcmp(count_token[match_string_index], "tag")) {
	  int value = atoi(match_string_token);

	  if ((value < 0) || (value > 65535)) {
	    printf("WARN: 'tag' has to be in the range 0-65535.\n");
	    exit(1);
	  }

	  request.data.id = value; 
	}
        else printf("WARN: ignoring unknown aggregation method: '%s'.\n", *count_token);
        match_string_index++;
      }

      memcpy(bufptr, &request, sizeof(struct query_entry));
      bufptr += sizeof(struct query_entry);
    }
  }

  /* arranging header and size of buffer to send */
  memcpy(clibuf, &q, sizeof(struct query_header)); 
  buflen = sizeof(struct query_header)+(q.num*sizeof(struct query_entry));
  buflen++;
  clibuf[buflen] = '\x4'; /* EOT */
  buflen++;

  sd = build_query_client(path);
  send(sd, clibuf, buflen, 0);

  /* reading results */ 
  if (want_stats || want_match) {
    unpacked = Recv(sd, &largebuf);
    if (want_all_fields) have_wtc = FALSE; 
    else have_wtc = TRUE; 
    what_to_count = ((struct query_header *)largebuf)->what_to_count;
    write_stats_header(what_to_count, have_wtc);
    elem = largebuf+sizeof(struct query_header);
    unpacked -= sizeof(struct query_header);
    while (printed < unpacked) {
      acc_elem = (struct pkt_data *) elem;
      if (memcmp(&acc_elem, &empty_addr, sizeof(struct pkt_primitives)) != 0) {
        if (!have_wtc || (what_to_count & COUNT_ID))
	  printf("%-5d  ", acc_elem->primitives.id);
#if defined (HAVE_L2)
	if (!have_wtc || (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC))) {
	  etheraddr_string(acc_elem->primitives.eth_shost, ethernet_address);
	  printf("%-17s  ", ethernet_address);
	}

	if (!have_wtc || (what_to_count & COUNT_DST_MAC)) {
	  etheraddr_string(acc_elem->primitives.eth_dhost, ethernet_address);
	  printf("%-17s  ", ethernet_address);
	} 

	if (!have_wtc || (what_to_count & COUNT_VLAN)) {
          printf("%-5d  ", acc_elem->primitives.vlan_id);
        }
#endif
	if (!have_wtc || (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST|COUNT_SRC_NET
	    |COUNT_SUM_NET|COUNT_SRC_AS|COUNT_SUM_AS))) {
#if defined ENABLE_IPV6
	  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("%-45d  ", ntohl(acc_elem->primitives.src_ip.address.ipv4.s_addr));
#else
	  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("%-15d  ", ntohl(acc_elem->primitives.src_ip.address.ipv4.s_addr));
#endif
	  else {
	    addr_to_str(ip_address, &acc_elem->primitives.src_ip);
#if defined ENABLE_IPV6
	    printf("%-45s  ", ip_address);
#else
	    printf("%-15s  ", ip_address);
#endif
	  }
	}

	if (!have_wtc || (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_DST_AS))) {
#if defined ENABLE_IPV6
	  if (what_to_count & COUNT_DST_AS) printf("%-45d  ", ntohl(acc_elem->primitives.dst_ip.address.ipv4.s_addr));
#else
	  if (what_to_count & COUNT_DST_AS) printf("%-15d  ", ntohl(acc_elem->primitives.dst_ip.address.ipv4.s_addr));
#endif
	  else {
	    addr_to_str(ip_address, &acc_elem->primitives.dst_ip);
#if defined ENABLE_IPV6
	    printf("%-45s  ", ip_address);
#else
	    printf("%-15s  ", ip_address);
#endif
	  }
	}

	if (!have_wtc || (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)))
	  printf("%-5d     ", acc_elem->primitives.src_port);

	if (!have_wtc || (what_to_count & COUNT_DST_PORT))
	  printf("%-5d     ", acc_elem->primitives.dst_port);

	if (!have_wtc || (what_to_count & COUNT_IP_PROTO))
	  printf("%-10s  ", _protocols[acc_elem->primitives.proto].name);

	if (!have_wtc || (what_to_count & COUNT_IP_TOS))
	  printf("%-3d    ", acc_elem->primitives.tos); 

        printf("%-10u  ", acc_elem->pkt_num); 

        if (!have_wtc || (what_to_count & COUNT_FLOWS))
	  printf("%-10u  ", acc_elem->flo_num); 

        printf("%u\n", acc_elem->pkt_len); 
        counter++;
      }
      elem += sizeof(struct pkt_data);
      printed += sizeof(struct pkt_data);
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
  else if (want_counter) {
    unsigned char *base;
    u_int32_t bcnt = 0, pcnt = 0, fcnt = 0; 
    int printed;

    unpacked = Recv(sd, &largebuf);
    base = largebuf+sizeof(struct query_header);
    acc_elem = (struct pkt_data *) base;
    for (printed = sizeof(struct query_header); printed < unpacked; printed += sizeof(struct pkt_data), acc_elem++) {
      if (sum_counters) {
	pcnt += acc_elem->pkt_num;
	fcnt += acc_elem->flo_num;
	bcnt += acc_elem->pkt_len;
      }
      else {
        if (which_counter == 0) printf("%u\n", acc_elem->pkt_len); /* print bytes */
        else if (which_counter == 1) printf("%u\n", acc_elem->pkt_num); /* print packets */
        else if (which_counter == 2) printf("%u %u %u\n", acc_elem->pkt_num, acc_elem->pkt_len, acc_elem->flo_num); /* print packets+bytes+flows */
        else if (which_counter == 3) printf("%u\n", acc_elem->flo_num); /* print flows */
      }
    }
      
    if (sum_counters) {
      if (which_counter == 0) printf("%u\n", bcnt); /* print bytes */
      else if (which_counter == 1) printf("%u\n", pcnt); /* print packets */
      else if (which_counter == 2) printf("%u %u %u\n", pcnt, bcnt, fcnt); /* print packets+bytes+flows */
      else if (which_counter == 3) printf("%u\n", fcnt); /* print flows */
    }
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
