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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __PKT_HANDLERS_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"

/* functions */
void evaluate_packet_handlers()
{
  int primitives, index = 0;

  while (channels_list[index].aggregation) { 
    primitives = 0;
    memset(&channels_list[index].phandler, 0, N_PRIMITIVES);

#if defined (HAVE_L2)
    if (channels_list[index].aggregation & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_mac_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_mac_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_DST_MAC|COUNT_SUM_MAC)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_mac_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_mac_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_VLAN) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = vlan_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_vlan_handler;
      primitives++;
    }
#endif

    if (channels_list[index].aggregation & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SRC_AS)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
      else if (config.acct_type == ACCT_NF) {
	if (channels_list[index].aggregation & COUNT_SRC_AS) {
	  if (config.nfacctd_as == NF_AS_KEEP) channels_list[index].phandler[primitives] = NF_src_as_handler;
	  else channels_list[index].phandler[primitives] = NF_src_host_handler;
	}
	else channels_list[index].phandler[primitives] = NF_src_host_handler;
      }
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_DST_HOST|COUNT_DST_NET|COUNT_DST_AS)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
      else if (config.acct_type == ACCT_NF) {
	if (channels_list[index].aggregation & COUNT_DST_AS) {
	  if (config.nfacctd_as == NF_AS_KEEP) channels_list[index].phandler[primitives] = NF_dst_as_handler; 
	  else channels_list[index].phandler[primitives] = NF_dst_host_handler;
	}
	else channels_list[index].phandler[primitives] = NF_dst_host_handler;
      }
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_port_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_DST_PORT|COUNT_SUM_PORT)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_port_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & (COUNT_SUM_HOST|COUNT_SUM_NET|COUNT_SUM_AS)) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
      else if (config.acct_type == ACCT_NF) {
        if (channels_list[index].aggregation & COUNT_SUM_AS) {
          if (config.nfacctd_as == NF_AS_KEEP) channels_list[index].phandler[primitives] = NF_src_as_handler;
          else channels_list[index].phandler[primitives] = NF_src_host_handler;
	}
        else channels_list[index].phandler[primitives] = NF_src_host_handler;
      }
      primitives++;
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
      else if (config.acct_type == ACCT_NF) {
        if (channels_list[index].aggregation & COUNT_SUM_AS) {
          if (config.nfacctd_as == NF_AS_KEEP) channels_list[index].phandler[primitives] = NF_dst_as_handler;
          else channels_list[index].phandler[primitives] = NF_dst_host_handler;
	}
        else channels_list[index].phandler[primitives] = NF_dst_host_handler;
      }
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_IP_TOS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ip_tos_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ip_tos_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_IP_PROTO) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ip_proto_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ip_proto_handler;
      primitives++;
    }
    if (channels_list[index].aggregation & COUNT_FLOWS) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = flows_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_flows_handler;
      primitives++;
    }

    if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = counters_handler;
    else if (config.acct_type == ACCT_NF) {
      if (config.nfacctd_time == NF_TIME_SECS) channels_list[index].phandler[primitives] = NF_counters_secs_handler;
      else if (config.nfacctd_time == NF_TIME_NEW) channels_list[index].phandler[primitives] = NF_counters_new_handler;
      else channels_list[index].phandler[primitives] = NF_counters_msecs_handler; /* default */
    }
    primitives++;

    if (config.acct_type == ACCT_PM) {
      if (channels_list[index].aggregation & COUNT_ID) {
	/* we infer 'pre_tag_map' from configuration because it's global */
        if (config.pre_tag_map) {
	  channels_list[index].phandler[primitives] = ptag_id_handler;
	  primitives++;
	}
	if (channels_list[index].id) { 
	  channels_list[index].phandler[primitives] = id_handler; 
	  primitives++;
	}
      }
    }
    else if (config.acct_type == ACCT_NF) {
      if (channels_list[index].aggregation & COUNT_ID) {
	/* we infer 'pre_tag_map' from configuration because it's global */
	if (config.pre_tag_map) {
	  channels_list[index].phandler[primitives] = ptag_id_handler;
	  primitives++;
	}
	if (channels_list[index].id) {
	  channels_list[index].phandler[primitives] = id_handler;
	  primitives++;
	}
      }
    } 

    index++;
  }
}

#if defined (HAVE_L2)
void src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->mac_ptr) memcpy(pdata->primitives.eth_shost, (pptrs->mac_ptr+ETH_ADDR_LEN), ETH_ADDR_LEN); 
}

void dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->mac_ptr) memcpy(pdata->primitives.eth_dhost, pptrs->mac_ptr, ETH_ADDR_LEN);
}

void vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  register u_int16_t *vlan_ptr;
  
  if (pptrs->vlan_ptr) {
    vlan_ptr = (u_int16_t *)pptrs->vlan_ptr;
    pdata->primitives.vlan_id = ntohs(*vlan_ptr);
  }
}
#endif

void src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.src_ip.address.ipv4.s_addr = ((struct my_iphdr *) pptrs->iph_ptr)->ip_src.s_addr;
    pdata->primitives.src_ip.family = AF_INET;
  }
#if defined ENABLE_IPV6 
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    memcpy(&pdata->primitives.src_ip.address.ipv6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, IP6AddrSz); 
    pdata->primitives.src_ip.family = AF_INET6;
  }
#endif
}

void dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct my_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr;
    pdata->primitives.dst_ip.family = AF_INET;
  }
#if defined ENABLE_IPV6 
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    memcpy(&pdata->primitives.dst_ip.address.ipv6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, IP6AddrSz);
    pdata->primitives.dst_ip.family = AF_INET6;
  }
#endif
}

void src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->l4_proto == IPPROTO_UDP || pptrs->l4_proto == IPPROTO_TCP)
    pdata->primitives.src_port = ntohs(((struct my_tlhdr *) pptrs->tlh_ptr)->src_port);
  else pdata->primitives.src_port = 0;
}

void dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->l4_proto == IPPROTO_UDP || pptrs->l4_proto == IPPROTO_TCP)
    pdata->primitives.dst_port = ntohs(((struct my_tlhdr *) pptrs->tlh_ptr)->dst_port);
  else pdata->primitives.dst_port = 0;
}

void ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  u_int32_t tos;

  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pdata->primitives.tos = ((struct my_iphdr *) pptrs->iph_ptr)->ip_tos;
  }
#if defined ENABLE_IPV6
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    tos = ntohl(((struct ip6_hdr *) pptrs->iph_ptr)->ip6_flow);
    tos = ((tos & 0x0ff00000) >> 20);
    pdata->primitives.tos = tos; 
  }
#endif
}

void ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.proto = pptrs->l4_proto;
}

void counters_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->l3_proto == ETHERTYPE_IP) pdata->pkt_len = htonl(ntohs(((struct my_iphdr *) pptrs->iph_ptr)->ip_len));
#if defined ENABLE_IPV6
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) pdata->pkt_len = htonl(ntohs(((struct ip6_hdr *) pptrs->iph_ptr)->ip6_plen)+IP6HdrSz);
#endif
  if (pptrs->pf) {
    pdata->pkt_num = htonl(pptrs->pf+1);
    pptrs->pf = 0;
  }
  else pdata->pkt_num = NBO_One; 
  // pdata->pkt_time = 0;
  pdata->pkt_time = ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec;
}

void id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.id = chptr->id;
}

void flows_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if (pptrs->new_flow) pdata->flo_num = NBO_One;
}

#if defined (HAVE_L2)
void NF_src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.eth_shost, pptrs->f_data+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
    break;
  default:
    break;
  }
}

void NF_dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.eth_dhost, pptrs->f_data+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
    break;
  default:
    break;
  }
}

void NF_vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.vlan_id, pptrs->f_data+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
    pdata->primitives.vlan_id = ntohs(pdata->primitives.vlan_id);
    break;
  default:
    break;
  }
}
#endif

void NF_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      memcpy(&pdata->primitives.src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len); 
      pdata->primitives.src_ip.family = AF_INET;
      break;
    }
#if defined ENABLE_IPV6
    if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      memcpy(&pdata->primitives.src_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
      pdata->primitives.src_ip.family = AF_INET6;
      break;
    }
#endif
    break;
  case 8:
    switch(hdr->aggregation) {
    case 3:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_3 *) pptrs->f_data)->src_prefix;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 5:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_5 *) pptrs->f_data)->src_prefix;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 7:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_7 *) pptrs->f_data)->srcaddr;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 8:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_8 *) pptrs->f_data)->srcaddr;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 11:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_11 *) pptrs->f_data)->src_prefix;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 13:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_13 *) pptrs->f_data)->src_prefix;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 14:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_14 *) pptrs->f_data)->src_prefix;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    default:
      pdata->primitives.src_ip.address.ipv4.s_addr = 0;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    }  
    break;
  default:
    pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->srcaddr.s_addr;
    pdata->primitives.src_ip.family = AF_INET;
    break;
  }
}

void NF_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    if (pptrs->l3_proto == ETHERTYPE_IP) {
      memcpy(&pdata->primitives.dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    }
#if defined ENABLE_IPV6
    if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      memcpy(&pdata->primitives.dst_ip.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
      pdata->primitives.dst_ip.family = AF_INET6;
      break;
    }
#endif
    break;
  case 8:
    switch(hdr->aggregation) {
    case 4:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_4 *) pptrs->f_data)->dst_prefix;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 5:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_5 *) pptrs->f_data)->dst_prefix;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 6:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_6 *) pptrs->f_data)->dstaddr;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 7:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_7 *) pptrs->f_data)->dstaddr;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 8:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_8 *) pptrs->f_data)->dstaddr;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 12:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_12 *) pptrs->f_data)->dst_prefix;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 13:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_13 *) pptrs->f_data)->dst_prefix;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 14:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_14 *) pptrs->f_data)->dst_prefix;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    default:
      pdata->primitives.dst_ip.address.ipv4.s_addr = 0;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    }
    break;
  default:
    pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->dstaddr.s_addr;
    pdata->primitives.dst_ip.family = AF_INET;
    break;
  }
}

void NF_src_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.src_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, tpl->tpl[NF9_SRC_AS].len); 
#if defined LITTLE_ENDIAN
    pdata->primitives.src_ip.address.ipv4.s_addr <<= 16; /* 32-to-16 bit */
#endif
    pdata->primitives.src_ip.family = AF_INET;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_1 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 3:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_3 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 5:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_5 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 9:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_9 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 11:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_11 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    case 13:
      pdata->primitives.src_ip.address.ipv4.s_addr = ((struct struct_export_v8_13 *) pptrs->f_data)->src_as;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    default:
      pdata->primitives.src_ip.address.ipv4.s_addr = 0;
      pdata->primitives.src_ip.family = AF_INET;
      break;
    }
    pdata->primitives.src_ip.address.ipv4.s_addr <<= 16; /* 32-to-16 bit */
    break;
  default:
    pdata->primitives.src_ip.address.ipv4.s_addr = htonl(ntohs(((struct struct_export_v5 *) pptrs->f_data)->src_as));
    pdata->primitives.src_ip.family = AF_INET;
    break;
  }
}

void NF_dst_as_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.dst_ip.address.ipv4, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, tpl->tpl[NF9_DST_AS].len);
#if defined LITTLE_ENDIAN
    pdata->primitives.dst_ip.address.ipv4.s_addr <<= 16; /* 32-to-16 bit */
#endif
    pdata->primitives.dst_ip.family = AF_INET;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_1 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 4:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_4 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 5:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_5 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 9:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_9 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 12:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_12 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    case 13:
      pdata->primitives.dst_ip.address.ipv4.s_addr = ((struct struct_export_v8_13 *) pptrs->f_data)->dst_as;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    default:
      pdata->primitives.dst_ip.address.ipv4.s_addr = 0;
      pdata->primitives.dst_ip.family = AF_INET;
      break;
    }
    pdata->primitives.dst_ip.address.ipv4.s_addr <<= 16; /* 32-to-16 bit */
    break;
  default:
    pdata->primitives.dst_ip.address.ipv4.s_addr = htonl(ntohs(((struct struct_export_v5 *) pptrs->f_data)->dst_as));
    pdata->primitives.dst_ip.family = AF_INET;
    break;
  }
}

void NF_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  
  switch(hdr->version) {
  case 9:
    if (((u_int8_t)*(pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off) == IPPROTO_UDP) ||
        ((u_int8_t)*(pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off) == IPPROTO_TCP)) {
      memcpy(&pdata->primitives.src_port, pptrs->f_data+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
      pdata->primitives.src_port = ntohs(pdata->primitives.src_port);
    }
    else pdata->primitives.src_port = 0;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 2:
      if ((((struct struct_export_v8_2 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_2 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.src_port = ntohs(((struct struct_export_v8_2 *) pptrs->f_data)->srcport);
      break;
    case 8:
      if ((((struct struct_export_v8_8 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_8 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.src_port = ntohs(((struct struct_export_v8_8 *) pptrs->f_data)->srcport);
      break;
    case 10:
      if ((((struct struct_export_v8_10 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_10 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.src_port = ntohs(((struct struct_export_v8_10 *) pptrs->f_data)->srcport);
      break;
    case 14:
      if ((((struct struct_export_v8_14 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_14 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.src_port = ntohs(((struct struct_export_v8_14 *) pptrs->f_data)->srcport);
      break;
    default:
      pdata->primitives.src_port = 0; 
      break;
    }
    break;
  default:
    if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
        ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP)
      pdata->primitives.src_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->srcport);
    else pdata->primitives.src_port = 0;
    break;
  }
}

void NF_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    if (((u_int8_t)*(pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off) == IPPROTO_UDP) ||
        ((u_int8_t)*(pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off) == IPPROTO_TCP)) {
      memcpy(&pdata->primitives.dst_port, pptrs->f_data+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
      pdata->primitives.dst_port = ntohs(pdata->primitives.dst_port);
    }
    else pdata->primitives.dst_port = 0;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 2:
      if ((((struct struct_export_v8_2 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_2 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.dst_port = ntohs(((struct struct_export_v8_2 *) pptrs->f_data)->dstport);
      break;
    case 8:
      if ((((struct struct_export_v8_8 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_8 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.dst_port = ntohs(((struct struct_export_v8_8 *) pptrs->f_data)->dstport);
      break;
    case 10:
      if ((((struct struct_export_v8_10 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_10 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.dst_port = ntohs(((struct struct_export_v8_10 *) pptrs->f_data)->dstport);
      break;
    case 14:
      if ((((struct struct_export_v8_14 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
          ((struct struct_export_v8_14 *) pptrs->f_data)->prot == IPPROTO_TCP) 
        pdata->primitives.dst_port = ntohs(((struct struct_export_v8_14 *) pptrs->f_data)->dstport);
      break;
    default:
      pdata->primitives.dst_port = 0;
      break;
    }
    break;
  default:
    if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
        ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP) 
      pdata->primitives.dst_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dstport);
    else pdata->primitives.dst_port = 0;
    break;
  }
}

void NF_ip_tos_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.tos, pptrs->f_data+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
    break;
  case 8:
    switch(hdr->aggregation) {
    case 6:
      pdata->primitives.tos = ((struct struct_export_v8_6 *) pptrs->f_data)->tos;
      break;
    case 7:
      pdata->primitives.tos = ((struct struct_export_v8_7 *) pptrs->f_data)->tos;
      break;
    case 8:
      pdata->primitives.tos = ((struct struct_export_v8_8 *) pptrs->f_data)->tos;
      break;
    case 9:
      pdata->primitives.tos = ((struct struct_export_v8_9 *) pptrs->f_data)->tos;
      break;
    case 10:
      pdata->primitives.tos = ((struct struct_export_v8_10 *) pptrs->f_data)->tos;
      break;
    case 11:
      pdata->primitives.tos = ((struct struct_export_v8_11 *) pptrs->f_data)->tos;
      break;
    case 12:
      pdata->primitives.tos = ((struct struct_export_v8_12 *) pptrs->f_data)->tos;
      break;
    case 13:
      pdata->primitives.tos = ((struct struct_export_v8_13 *) pptrs->f_data)->tos;
      break;
    case 14:
      pdata->primitives.tos = ((struct struct_export_v8_14 *) pptrs->f_data)->tos;
      break;
    default:
      pdata->primitives.tos = 0;
      break;
    }
    break;
  default:
    pdata->primitives.tos = ((struct struct_export_v5 *) pptrs->f_data)->tos;
    break;
  }
}

void NF_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->primitives.proto, pptrs->f_data+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
    break;
  case 8:
    switch(hdr->aggregation) {
    case 2:
      pdata->primitives.proto = ((struct struct_export_v8_2 *) pptrs->f_data)->prot;
      break;
    case 8:
      pdata->primitives.proto = ((struct struct_export_v8_8 *) pptrs->f_data)->prot;
      break;
    case 10:
      pdata->primitives.proto = ((struct struct_export_v8_10 *) pptrs->f_data)->prot;
      break;
    case 14:
      pdata->primitives.proto = ((struct struct_export_v8_14 *) pptrs->f_data)->prot;
      break;
    default:
      pdata->primitives.proto = 0;
      break;
    }
    break;
  default:
    pdata->primitives.proto = ((struct struct_export_v5 *) pptrs->f_data)->prot;
    break;
  }
}

/* times from the netflow engine are in msecs */
void NF_counters_msecs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  time_t fstime;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->pkt_len, pptrs->f_data+tpl->tpl[NF9_IN_BYTES].off, tpl->tpl[NF9_IN_BYTES].len);
    memcpy(&pdata->pkt_num, pptrs->f_data+tpl->tpl[NF9_IN_PACKETS].off, tpl->tpl[NF9_IN_PACKETS].len);
    memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
    pdata->pkt_time = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime))/1000);
    break;
  case 8:
    switch(hdr->aggregation) {
    case 6:
      pdata->pkt_len = ((struct struct_export_v8_6 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_6 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_6 *) pptrs->f_data)->First))/1000);
      break;
    case 7:
      pdata->pkt_len = ((struct struct_export_v8_7 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_7 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_7 *) pptrs->f_data)->First))/1000);
      break;
    case 8:
      pdata->pkt_len = ((struct struct_export_v8_8 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_8 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_8 *) pptrs->f_data)->First))/1000);
      break;
    default:
      pdata->pkt_len = ((struct struct_export_v8_1 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_1 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_1 *) pptrs->f_data)->First))/1000);
      break;
    }
    break;
  default:
    pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
    pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
    pdata->pkt_time = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First))/1000); 
    break;
  }
}

/* times from the netflow engine are in secs */
void NF_counters_secs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  time_t fstime;
  
  switch(hdr->version) {
  case 9:
    memcpy(&pdata->pkt_len, pptrs->f_data+tpl->tpl[NF9_IN_BYTES].off, tpl->tpl[NF9_IN_BYTES].len);
    memcpy(&pdata->pkt_num, pptrs->f_data+tpl->tpl[NF9_IN_PACKETS].off, tpl->tpl[NF9_IN_PACKETS].len);
    memcpy(&fstime, pptrs->f_data+tpl->tpl[NF9_FIRST_SWITCHED].off, tpl->tpl[NF9_FIRST_SWITCHED].len);
    pdata->pkt_time = ntohl(((struct struct_header_v9 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v9 *) pptrs->f_header)->SysUptime)-ntohl(fstime));
    break;
  case 8:
    switch(hdr->aggregation) {
    case 6:
      pdata->pkt_len = ((struct struct_export_v8_6 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_6 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
       (ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_6 *) pptrs->f_data)->First));
      break;
    case 7:
      pdata->pkt_len = ((struct struct_export_v8_7 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_7 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
       (ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_7 *) pptrs->f_data)->First));
      break;
    case 8:
      pdata->pkt_len = ((struct struct_export_v8_8 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_8 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
       (ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_8 *) pptrs->f_data)->First));
      break;
    default:
      pdata->pkt_len = ((struct struct_export_v8_1 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_1 *) pptrs->f_data)->dPkts;
      pdata->pkt_time = ntohl(((struct struct_header_v8 *) pptrs->f_header)->unix_secs)-
       (ntohl(((struct struct_header_v8 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v8_1 *) pptrs->f_data)->First));
      break;
    }
    break;
  default:
    pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
    pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
    pdata->pkt_time = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
      (ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First));
    break;
  }
}

/* ignore netflow engine times and generate new ones */
void NF_counters_new_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->pkt_len, pptrs->f_data+tpl->tpl[NF9_IN_BYTES].off, tpl->tpl[NF9_IN_BYTES].len);
    memcpy(&pdata->pkt_num, pptrs->f_data+tpl->tpl[NF9_IN_PACKETS].off, tpl->tpl[NF9_IN_PACKETS].len);
    pdata->pkt_time = 0;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 6:
      pdata->pkt_len = ((struct struct_export_v8_6 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_6 *) pptrs->f_data)->dPkts;
      break;
    case 7:
      pdata->pkt_len = ((struct struct_export_v8_7 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_7 *) pptrs->f_data)->dPkts;
      break;
    case 8:
      pdata->pkt_len = ((struct struct_export_v8_8 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_8 *) pptrs->f_data)->dPkts;
      break;
    default:
      pdata->pkt_len = ((struct struct_export_v8_1 *) pptrs->f_data)->dOctets;
      pdata->pkt_num = ((struct struct_export_v8_1 *) pptrs->f_data)->dPkts;
      break;
    }
    pdata->pkt_time = 0;
    break;
  default:
    pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
    pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
    pdata->pkt_time = 0;
    break;
  }
}

void ptag_id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.id = pptrs->tag;
}

void NF_flows_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    memcpy(&pdata->flo_num, pptrs->f_data+tpl->tpl[NF9_FLOWS].off, tpl->tpl[NF9_FLOWS].len);
    if (!pdata->flo_num) pdata->flo_num = NBO_One;
    break;
  case 8:
    switch(hdr->aggregation) {
    case 6:
    case 7:
    case 8:
      break;
    default:
      pdata->flo_num = ((struct struct_export_v8_1 *) pptrs->f_data)->dFlows;
      break;
    }
    break;
  default:
    pdata->flo_num = NBO_One;
    break;
  }
}
