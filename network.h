/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2004 by Paolo Lucente
*/

#include "include/extract.h"
#include "include/llc.h"
#include "include/sll.h"
#include "include/ieee802_11.h"
#include "include/fddi.h"

#define min(a,b) ((a)>(b)?(b):(a))

#define ETH_ADDR_LEN    	6               /* Octets in one ethernet addr   */
#define ETHER_HDRLEN    	14
#define ETHERMTU		1500
#define IEEE8021Q_TAGLEN	4
#define PPP_TAGLEN              2

/* 10Mb/s ethernet header */
struct eth_header
{
  u_int8_t  ether_dhost[ETH_ADDR_LEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ADDR_LEN];      /* source ether addr    */
  u_int16_t ether_type;                     /* packet type ID field */
};

/* Ethernet protocol ID's */
#define ETHERTYPE_IP		0x0800          /* IP */
#define ETHERTYPE_PPPOE         0x8864          /* pppoe (session stage) */
#define ETHERTYPE_8021Q		0x8100          /* 802.1Q */

/* PPP protocol definitions */
#define PPP_HDRLEN      4       /* octets for standard ppp header */
#define PPPOE_HDRLEN	6	/* octets for standard pppoe header  */
#define PPP_IP          0x0021  /* Internet Protocol */

struct my_iphdr
{
   u_int8_t     ip_vhl;         /* header length, version */
#define IP_V(ip)        (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)
   u_int8_t     ip_tos;         /* type of service */
   u_int16_t    ip_len;         /* total length */
   u_int16_t    ip_id;          /* identification */
   u_int16_t    ip_off;         /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
   u_int8_t     ip_ttl;         /* time to live */
   u_int8_t     ip_p;           /* protocol */
   u_int16_t    ip_sum;         /* checksum */
   struct in_addr ip_src;	/* source and destination addresses */
   struct in_addr ip_dst; 
};

struct my_tlhdr {
   u_int16_t	src_port;	/* source and destination ports */
   u_int16_t	dst_port;
};

struct packet_ptrs {
  struct pcap_pkthdr *pkthdr; /* ptr to header structure passed by libpcap */
  u_char *f_agent; /* ptr to flow export agent */ 
  u_char *f_header; /* ptr to netflow packet header */ 
  u_char *f_data; /* ptr to netflow data */ 
  u_char *idtable; /* ptr to id table map */
  u_char *packet_ptr; /* ptr to the whole packet */
  u_char *mac_ptr; /* ptr to mac addresses */
  u_char *vlan_ptr; /* ptr to vlan id */
  u_char *iph_ptr; /* ptr to ip header */
  u_char *tlh_ptr; /* ptr to transport level protocol header */
};

struct pkt_primitives {
  u_int8_t eth_dhost[ETH_ADDR_LEN];
  u_int8_t eth_shost[ETH_ADDR_LEN];
  u_int16_t vlan_id;
  struct in_addr src_ip;
  struct in_addr dst_ip;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t proto;
  u_int16_t id;
};

struct pkt_data {
  struct pkt_primitives primitives;
  u_int32_t pkt_len;
  u_int32_t pkt_num;
  u_int32_t pkt_time;
};
