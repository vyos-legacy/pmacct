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

    if (channels_list[index].aggregation & COUNT_SRC_MAC) {
      if (config.acct_type == ACCT_PM) {
	channels_list[index].phandler[primitives] = src_mac_handler;
	primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_DST_MAC) {
      if (config.acct_type == ACCT_PM) {
	channels_list[index].phandler[primitives] = dst_mac_handler;
        primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_VLAN) {
      if (config.acct_type == ACCT_PM) {
	channels_list[index].phandler[primitives] = vlan_handler;
	primitives++;
      }
    }

    if (channels_list[index].aggregation & COUNT_SRC_HOST) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_host_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_DST_HOST) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_host_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_SRC_PORT) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_port_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_DST_PORT) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_port_handler;
       else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_port_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_SUM_HOST) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = src_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_src_host_handler;
      primitives++;
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = dst_host_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_dst_host_handler;
      primitives++;
    }

    if (channels_list[index].aggregation & COUNT_IP_PROTO) {
      if (config.acct_type == ACCT_PM) channels_list[index].phandler[primitives] = ip_proto_handler;
      else if (config.acct_type == ACCT_NF) channels_list[index].phandler[primitives] = NF_ip_proto_handler;
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
	channels_list[index].phandler[primitives] = id_handler; 
	primitives++;
      }
    }
    else if (config.acct_type == ACCT_NF) {
      if (channels_list[index].aggregation & COUNT_ID) {
	/* we infer 'pre_tag_map' from configuration because it's global */
	if (config.pre_tag_map) {
	  channels_list[index].phandler[primitives] = NF_id_handler;
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

void src_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  memcpy(pdata->primitives.eth_shost, (pptrs->mac_ptr+ETH_ADDR_LEN), ETH_ADDR_LEN); 
}

void dst_mac_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  memcpy(pdata->primitives.eth_dhost, pptrs->mac_ptr, ETH_ADDR_LEN);
}

void vlan_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  register u_int16_t *vlan_ptr;
  
  if (pptrs->vlan_ptr) {
    vlan_ptr = (u_int16_t *)pptrs->vlan_ptr;
    pdata->primitives.vlan_id = ntohs(*vlan_ptr);
  }
  else pdata->primitives.vlan_id = 0;
}

void src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.src_ip.s_addr = ((struct my_iphdr *) pptrs->iph_ptr)->ip_src.s_addr;
}

void dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.dst_ip.s_addr = ((struct my_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr;
}

void src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if ((((struct my_iphdr *) pptrs->iph_ptr)->ip_p == IPPROTO_UDP) ||
      ((struct my_iphdr *) pptrs->iph_ptr)->ip_p == IPPROTO_TCP)
    pdata->primitives.src_port = ntohs(((struct my_tlhdr *) pptrs->tlh_ptr)->src_port);
  else pdata->primitives.src_port = 0;
}

void dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if ((((struct my_iphdr *) pptrs->iph_ptr)->ip_p == IPPROTO_UDP) ||
      ((struct my_iphdr *) pptrs->iph_ptr)->ip_p == IPPROTO_TCP)
    pdata->primitives.dst_port = ntohs(((struct my_tlhdr *) pptrs->tlh_ptr)->dst_port);
  else pdata->primitives.dst_port = 0;
}

void ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.proto = ((struct my_iphdr *) pptrs->iph_ptr)->ip_p;
}

void counters_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->pkt_len = htonl(ntohs(((struct my_iphdr *) pptrs->iph_ptr)->ip_len));
  pdata->pkt_num = NBO_One; 
  pdata->pkt_time = 0;
}

void id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.id = chptr->id;
}

void NF_src_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.src_ip.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->srcaddr.s_addr;
}

void NF_dst_host_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.dst_ip.s_addr = ((struct struct_export_v5 *) pptrs->f_data)->dstaddr.s_addr;
}

void NF_src_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
      ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP)
    pdata->primitives.src_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->srcport);
  else pdata->primitives.src_port = 0;
}

void NF_dst_port_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  if ((((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_UDP) ||
      ((struct struct_export_v5 *) pptrs->f_data)->prot == IPPROTO_TCP)
    pdata->primitives.dst_port = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dstport);
  else pdata->primitives.dst_port = 0;
}

void NF_ip_proto_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.proto = ((struct struct_export_v5 *) pptrs->f_data)->prot;
}

/* times from the netflow engine are in msecs */
void NF_counters_msecs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
  pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
  pdata->pkt_time = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
   ((ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First))/1000); 
}

/* times from the netflow engine are in secs */
void NF_counters_secs_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
  pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
  pdata->pkt_time = ntohl(((struct struct_header_v5 *) pptrs->f_header)->unix_secs)-
   (ntohl(((struct struct_header_v5 *) pptrs->f_header)->SysUptime)-ntohl(((struct struct_export_v5 *) pptrs->f_data)->First));
}

/* ignore netflow engine times and generate new ones */
void NF_counters_new_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->pkt_len = ((struct struct_export_v5 *) pptrs->f_data)->dOctets;
  pdata->pkt_num = ((struct struct_export_v5 *) pptrs->f_data)->dPkts;
  pdata->pkt_time = 0;
}

void NF_id_handler(struct channels_list_entry *chptr, struct packet_ptrs *pptrs, struct pkt_data *pdata)
{
  pdata->primitives.id = ((struct my_iphdr *)pptrs->iph_ptr)->ip_id; 
}
