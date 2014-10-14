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
#define ARGS_NFACCTD "n:dDhP:b:f:F:c:m:p:r:s:S:l:v:o:"
#define ARGS_PMACCTD "n:NdDhP:b:f:F:c:i:I:m:p:r:s:S:v:o:w"
#define ARGS_PMACCT "Ssc:etm:p:P:M:arN:n:"
#define N_PRIMITIVES 21
#define N_FUNCS 10 
#define MAX_N_PLUGINS 32
#define PROTO_LEN 12
#define MAX_MAP_ENTRIES 128

#if defined ENABLE_IPV6
#define DEFAULT_SNAPLEN 128
#else
#define DEFAULT_SNAPLEN 68
#endif

#define SRVBUFLEN 256
#define LONGSRVBUFLEN 384
#define LONGLONGSRVBUFLEN 1024
#define LARGEBUFLEN 8192

#define MANTAINER "Paolo Lucente <paolo.lucente@ic.cnr.it>"
#define PMACCTD_USAGE_HEADER "Promiscuous Mode Accounting Daemon, pmacctd 0.8.3"
#define PMACCT_USAGE_HEADER "pmacct, pmacct client 0.8.3"
#define PMMYPLAY_USAGE_HEADER "pmmyplay, pmacct MySQL logfile player 0.8.3"
#define PMPGPLAY_USAGE_HEADER "pmpgplay, pmacct PGSQL logfile player 0.8.3"
#define NFACCTD_USAGE_HEADER "NetFlow Accounting Daemon, nfacctd 0.8.3"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define ERR -1
#define SUCCESS 0

#define	E_NOTFOUND	2

#define MIN(x, y) (x <= y ? x : y)

/* acct_type */ 
#define ACCT_PM		1	/* promiscuous mode */
#define ACCT_NF		2	/* netflow */

#define COUNT_SRC_HOST		0x00000001
#define COUNT_DST_HOST		0x00000002
#define COUNT_SUM_HOST          0x00000004 
#define COUNT_SRC_PORT          0x00000008 
#define COUNT_DST_PORT          0x00000010 
#define COUNT_IP_PROTO          0x00000020 
#define COUNT_SRC_MAC           0x00000040 
#define COUNT_DST_MAC           0x00000080
#define COUNT_SRC_NET		0x00000100
#define COUNT_DST_NET		0x00000200
#define COUNT_ID		0x00000400	
#define COUNT_VLAN		0x00000800	
#define COUNT_IP_TOS		0x00001000	
#define COUNT_NONE		0x00002000	
#define COUNT_SRC_AS		0x00004000
#define COUNT_DST_AS		0x00008000
#define COUNT_SUM_NET		0x00010000
#define COUNT_SUM_AS		0x00020000
#define COUNT_SUM_PORT		0x00040000
#define TIMESTAMP               0x00080000 /* USE_TIMESTAMPS */

/* BYTES and PACKETS are used into templates; we let their values to
   overlap with some values we will not need into templates */ 
#define BYTES			COUNT_SRC_NET
#define PACKETS			COUNT_DST_NET

#define FAKE_SRC_MAC		0x00000001
#define FAKE_DST_MAC		0x00000002
#define FAKE_SRC_HOST		0x00000004
#define FAKE_DST_HOST		0x00000008

#define COUNT_MINUTELY          0x00000001
#define COUNT_HOURLY            0x00000002
#define COUNT_DAILY             0x00000004
#define COUNT_WEEKLY		0x00000008
#define COUNT_MONTHLY		0x00000010

#define WANT_STATS		0x00000001
#define WANT_ERASE		0x00000002
#define WANT_STATUS		0x00000004
#define WANT_COUNTER		0x00000008
#define WANT_MATCH		0x00000010
#define WANT_RESET		0x00000020

