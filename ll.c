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

  eth_pk = (struct eth_header *) pptrs->packet_ptr;
  etype = ntohs(eth_pk->ether_type);
  pptrs->mac_ptr = (u_char *) eth_pk->ether_dhost; 
  pptrs->vlan_ptr = NULL; /* avoid stale vlan pointers */

  if (etype == ETHERTYPE_IP) {
    pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN;
    return;
  }

  /* contributed by Rich Gade */
  else if (etype == ETHERTYPE_8021Q) {
    e8021Q = (u_int16_t *)(pptrs->packet_ptr + sizeof(struct eth_header) + 2);
    if (ntohs(*e8021Q) == ETHERTYPE_IP) { 
      pptrs->vlan_ptr = pptrs->packet_ptr + ETHER_HDRLEN; 
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN; 
      return;
    }
  }

  /* contributed by Vasiliy */
  else if (etype == ETHERTYPE_PPPOE) {
    ppp = (u_int16_t *)(pptrs->packet_ptr + sizeof(struct eth_header) + PPPOE_HDRLEN);
    if (ntohs(*ppp) == PPP_IP) {
      pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN + PPPOE_HDRLEN + PPP_TAGLEN;
      return;
    }
  }

  pptrs->iph_ptr = NULL;
}

void fddi_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs) 
{
  register u_char *p;
  u_int caplen = h->caplen;
  struct fddi_header *fddi_pk;

  p = pptrs->packet_ptr;
  fddi_pk = (struct fddi_header *) pptrs->packet_ptr;
  if ((fddi_pk->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
    pptrs->mac_ptr = (u_char *) fddi_pk->fddi_dhost; 

    /* going up to LLC/SNAP layer header */
    p += FDDI_HDRLEN;
    caplen -= FDDI_HDRLEN;
    if ((p = llc_handler(h, caplen, p)) != NULL) pptrs->iph_ptr = p;
    return;
  }

  pptrs->iph_ptr = NULL; 
}

/*
 rough and simple ppp support. It's just a 3 lines hack
 done in a rainy August afternoon with no ethernet host
 available.
                Gianluca
*/
void ppp_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  if ((*(pptrs->packet_ptr+2) == PPP_IP) ||
      (*(pptrs->packet_ptr+2) == ETHERTYPE_IP)) {
    pptrs->iph_ptr = pptrs->packet_ptr + PPP_HDRLEN;
    return;
  }

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

  p = pptrs->packet_ptr;

  fc = EXTRACT_LE_16BITS(p);
  if (FC_TYPE(fc) == T_DATA) {
    if (FC_TO_DS(fc) && FC_FROM_DS(fc)) hdrlen = 30;
    else hdrlen = 24;
    caplen -= hdrlen;
    p += hdrlen;
    if (!FC_WEP(fc)) {
      if ((p = llc_handler(h, caplen, p)) != NULL) pptrs->iph_ptr = p;
      return;
    }
  }
  
  pptrs->iph_ptr = NULL;
}

void sll_handler(const struct pcap_pkthdr *h, register struct packet_ptrs *pptrs)
{
  register const struct sll_header *sllp;
  register u_short etype;
  u_char *p;
  u_int caplen = h->caplen;

  p = pptrs->packet_ptr;
  sllp = (const struct sll_header *) pptrs->packet_ptr;
  etype = ntohs(sllp->sll_protocol);

  if (etype == ETHERTYPE_IP) {
    pptrs->iph_ptr = (u_char *)(pptrs->packet_ptr + SLL_HDR_LEN);
    return;
  }
  else if (etype == LINUX_SLL_P_802_2) {
    /* going up to LLC/SNAP layer header */
    p += SLL_HDR_LEN;
    caplen -= SLL_HDR_LEN;
    if ((p = llc_handler(h, caplen, p)) != NULL) pptrs->iph_ptr = p;
    return;
  }

  pptrs->iph_ptr = NULL;
}

u_char *llc_handler(const struct pcap_pkthdr *h, u_int caplen, register u_char *buf)
{
  struct llc llc;

  memcpy((char *)&llc, (char *) buf, min(caplen, sizeof(llc)));
  if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
      && llc.ctl.snap.snap_ui == LLC_UI) {
    if (EXTRACT_16BITS(&llc.ctl.snap_ether.snap_ethertype[0]) == ETHERTYPE_IP)
      return (u_char *)(buf + min(caplen, sizeof(llc)));
    else return 0; 
  }
  else return 0;
}
