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
#define __LL_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"

/* eth_handler() picks a whole packet, reads
   informtions contained in the link layer
   protocol header and fills a pointer structure */ 
void eth_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs) 
{
  u_int16_t *e8021Q;
  u_int16_t *ppp;
  struct eth_header *eth_pk;
  register u_short etype;
  register u_int16_t caplen = h->caplen;

  if (caplen < ETHER_HDRLEN) {
    pptrs->iph_ptr = NULL;
    return;
  }

  eth_pk = (struct eth_header *) pptrs->packet_ptr;
  etype = ntohs(eth_pk->ether_type);
  pptrs->mac_ptr = (u_char *) eth_pk->ether_dhost; 
  pptrs->vlan_ptr = NULL; /* avoid stale vlan pointers */

  if (etype == ETHERTYPE_IP) {
    pptrs->l3_proto = ETHERTYPE_IP; 
    pptrs->l3_handler = ip_handler;
    pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN;
    return;
  }
#if defined ENABLE_IPV6
  if (etype == ETHERTYPE_IPV6) {
    pptrs->l3_proto = ETHERTYPE_IPV6;
    pptrs->l3_handler = ip6_handler;
    pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN;
    return;
  }
#endif

  /* originally contributed by Rich Gade */
  if (etype == ETHERTYPE_8021Q) {
    if (caplen < ETHER_HDRLEN+IEEE8021Q_TAGLEN) {
      pptrs->iph_ptr = NULL;
      return;
    }
    e8021Q = (u_int16_t *)(pptrs->packet_ptr + sizeof(struct eth_header) + 2);
    pptrs->vlan_ptr = pptrs->packet_ptr + ETHER_HDRLEN; 
    etype = ntohs(*e8021Q);
    if (etype == ETHERTYPE_IP) { 
      pptrs->l3_proto = ETHERTYPE_IP;
      pptrs->l3_handler = ip_handler;
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN; 
      return;
    }
#if defined ENABLE_IPV6
    if (etype == ETHERTYPE_IPV6) {
      pptrs->l3_proto = ETHERTYPE_IPV6;
      pptrs->l3_handler = ip6_handler;
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN; 
      return;
    }
#endif 
  }

  /* originally contributed by Vasiliy Ponomarev */
  if (etype == ETHERTYPE_PPPOE) {
    if (caplen < ETHER_HDRLEN+PPPOE_HDRLEN+PPP_TAGLEN) {
      pptrs->iph_ptr = NULL;
      return;
    }
    ppp = (u_int16_t *)(pptrs->packet_ptr + sizeof(struct eth_header) + PPPOE_HDRLEN);
    etype = ntohs(*ppp);
    if (etype == PPP_IP) {
      pptrs->l3_proto = ETHERTYPE_IP; 
      pptrs->l3_handler = ip_handler;
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + PPPOE_HDRLEN + PPP_TAGLEN;
      return;
    }
#if defined ENABLE_IPV6
    if (etype == PPP_IPV6) {
      pptrs->l3_proto = ETHERTYPE_IPV6;
      pptrs->l3_handler = ip6_handler;
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + PPPOE_HDRLEN + PPP_TAGLEN;
      return;
    }
#endif
  }

  pptrs->l3_proto = 0;
  pptrs->l3_handler = NULL;
  pptrs->iph_ptr = NULL;
}

void fddi_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs) 
{
  register u_char *p;
  u_int caplen = h->caplen;
  struct fddi_header *fddi_pk;

  if (caplen < FDDI_HDRLEN) {
    pptrs->iph_ptr = NULL;
    return;
  }

  p = pptrs->packet_ptr;
  fddi_pk = (struct fddi_header *) pptrs->packet_ptr;
  if ((fddi_pk->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
    pptrs->mac_ptr = (u_char *) fddi_pk->fddi_dhost; 

    /* going up to LLC/SNAP layer header */
    p += FDDI_HDRLEN;
    caplen -= FDDI_HDRLEN;
    if ((p = llc_handler(h, caplen, p, pptrs)) != NULL) {
      pptrs->iph_ptr = p;
      return;
    }
  }

  pptrs->iph_ptr = NULL; 
}

void ppp_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  u_char *p = pptrs->packet_ptr;
  register u_int16_t len = h->len;
  register u_int16_t caplen = h->caplen;
  register unsigned int proto = 0;

  if ((caplen < PPP_HDRLEN) || (len < 2)) {
    pptrs->iph_ptr = NULL;
    return;
  }

  if (*p == PPP_ADDRESS && *(p + 1) == PPP_CONTROL) {
    p += 2;
    len -= 2;
    if (len < 2) {
      pptrs->iph_ptr = NULL;
      return;
    }
  }
   
  if (*p % 2) {
    proto = *p;
    p++;
  }
  else {
    proto = EXTRACT_16BITS(p);
    p += 2;
  }

  if ((proto == PPP_IP) || (proto == ETHERTYPE_IP)) { 
    pptrs->l3_proto = ETHERTYPE_IP; 
    pptrs->l3_handler = ip_handler;
    pptrs->iph_ptr = p;
    return;
  }
#if defined ENABLE_IPV6
  if ((proto == PPP_IPV6) || (proto == ETHERTYPE_IPV6)) {
    pptrs->l3_proto = ETHERTYPE_IPV6;
    pptrs->l3_handler = ip6_handler;
    pptrs->iph_ptr = p;
    return;
  }
#endif

  pptrs->l3_proto = 0;
  pptrs->l3_handler = NULL;
  pptrs->iph_ptr = NULL;
}

/*
  support for 802.11 Wireless LAN protocol. I'm writing
  it during a sad morning spent at Fiumicino's Airport
  because of Alitalia strikes. It's currently working
  well for me at FCO WiFi zone. Let me know. 

			28-11-2003, Paolo. 
*/
void ieee_802_11_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  u_int16_t fc;
  u_int caplen = h->caplen;
  short int hdrlen;
  u_char *p;

  if (caplen < IEEE802_11_FC_LEN) {
    pptrs->iph_ptr = NULL;
    return;
  }

  p = pptrs->packet_ptr;

  fc = EXTRACT_LE_16BITS(p);
  if (FC_TYPE(fc) == T_DATA) {
    if (FC_TO_DS(fc) && FC_FROM_DS(fc)) hdrlen = 30;
    else hdrlen = 24;
    if (caplen < hdrlen) {
      pptrs->iph_ptr = NULL;
      return;
    }
    caplen -= hdrlen;
    p += hdrlen;
    if (!FC_WEP(fc)) {
      if ((p = llc_handler(h, caplen, p, pptrs)) != NULL) {
	pptrs->iph_ptr = p;
        return;
      }
    }
  }
  
  pptrs->l3_proto = 0;
  pptrs->l3_handler = NULL;
  pptrs->iph_ptr = NULL;
}

void raw_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  register u_int16_t caplen = h->caplen;
  struct my_iphdr *hdr;

  if (caplen < 4) {
    pptrs->iph_ptr = NULL;
    return;
  } 

  hdr = (struct my_iphdr *) pptrs->packet_ptr;
  switch (IP_V(hdr)) {
  case 4:
    pptrs->iph_ptr = pptrs->packet_ptr; 
    pptrs->l3_proto = ETHERTYPE_IP;
    pptrs->l3_handler = ip_handler;
    return;
#if defined ENABLE_IPV6
  case 6:
    pptrs->iph_ptr = pptrs->packet_ptr;
    pptrs->l3_proto = ETHERTYPE_IPV6;
    pptrs->l3_handler = ip6_handler;
    return;
#endif
  default:
    pptrs->iph_ptr = NULL;
    pptrs->l3_proto = 0;
    pptrs->l3_handler = NULL; 
    return;
  }
}

void sll_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  register const struct sll_header *sllp;
  register u_short etype;
  u_char *p;
  u_int caplen = h->caplen;

  if (caplen < SLL_HDR_LEN) {
    pptrs->iph_ptr = NULL;
    return;
  }

  p = pptrs->packet_ptr;
  sllp = (const struct sll_header *) pptrs->packet_ptr;
  etype = ntohs(sllp->sll_protocol);

  if (etype == ETHERTYPE_IP) {
    pptrs->l3_proto = ETHERTYPE_IP;
    pptrs->l3_handler = ip_handler; 
    pptrs->iph_ptr = (u_char *)(pptrs->packet_ptr + SLL_HDR_LEN);
    return;
  }
  
  /* XXX: ETHERTYPE_IPV6 ? */

  if (etype == LINUX_SLL_P_802_2) {
    /* going up to LLC/SNAP layer header */
    p += SLL_HDR_LEN;
    caplen -= SLL_HDR_LEN;
    if ((p = llc_handler(h, caplen, p, pptrs)) != NULL) {
      pptrs->iph_ptr = p;
      return;
    }
  }

  pptrs->l3_proto = 0;
  pptrs->l3_handler = NULL;
  pptrs->iph_ptr = NULL;
}

u_char *llc_handler(const struct pcap_pkthdr *h, u_int caplen, register u_char *buf, register struct packet_ptrs *pptrs)
{
  struct llc llc;
  register u_short etype;

  if (caplen < 3) return NULL;

  memcpy((char *)&llc, (char *) buf, min(caplen, sizeof(llc)));
  if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
      && llc.ctl.snap.snap_ui == LLC_UI) {
    etype = EXTRACT_16BITS(&llc.ctl.snap_ether.snap_ethertype[0]);
    if (etype == ETHERTYPE_IP) {
      pptrs->l3_proto = ETHERTYPE_IP;
      pptrs->l3_handler = ip_handler;
      return (u_char *)(buf + min(caplen, sizeof(llc)));
    }
#if defined ENABLE_IPV6
    if (etype == ETHERTYPE_IPV6) {
      pptrs->l3_proto = ETHERTYPE_IPV6;
      pptrs->l3_handler = ip6_handler;
      return (u_char *)(buf + min(caplen, sizeof(llc)));
    }
#endif
    else return 0; 
  }
  else return 0;
}
