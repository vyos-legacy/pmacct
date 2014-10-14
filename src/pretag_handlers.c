/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2006 by Paolo Lucente
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

#define __PRETAG_HANDLERS_C

#include "pmacct.h"
#include "nfacctd.h"
#include "sflow.h"
#include "sfacctd.h"
#include "pretag_handlers.h"
#include "pretag-data.h"
#include "net_aggr.h"

int PT_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int j;

  j = atoi(value);
  if (!j || j > 65535) {
    Log(LOG_ERR, "ERROR ( %s ): Agent ID '%d' is invalid (range: 0 > ID > 65535). ", filename, j);
    return TRUE;
  } 
  e->id = j; 

  return FALSE;
}

int PT_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  if (!str_to_addr(value, &e->agent_ip)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad IP address '%s'. ", filename, value);
    return TRUE;
  }

  return FALSE;
}

int PT_map_input_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'in' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }
  
  e->input = atoi(value);
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_input_handler; 
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_input_handler; 

  return FALSE;
}

int PT_map_output_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'out' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  e->output = atoi(value);
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_output_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_output_handler;

  return FALSE;
}

int PT_map_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0;

  if (!str_to_addr(value, &e->nexthop)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad nexthop address '%s'. ", filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_nexthop_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_nexthop_handler;

  return FALSE;
}

int PT_map_bgp_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0;

  if (!str_to_addr(value, &e->bgp_nexthop)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad BGP nexthop address '%s'. ", filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_bgp_nexthop_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_bgp_nexthop_handler;

  return FALSE;
}

int PT_map_engine_type_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0, j, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'engine_type' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_ERR, "ERROR ( %s ): bad 'engine_type' value (range: 0 >= value > 256). ", filename);
    return TRUE;
  }
  e->engine_type = j; 
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_engine_type_handler;

  return FALSE;
}

int PT_map_engine_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0, j, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'engine_id' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_ERR, "ERROR ( %s ): bad 'engine_id' value (range: 0 >= value > 256). ", filename);
    return TRUE;
  }
  e->engine_id = j;
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_engine_id_handler;

  return FALSE;
}

int PT_map_filter_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  struct pcap_device device;
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  char errbuf[PCAP_ERRBUF_SIZE];
  int x;

  memset(&device, 0, sizeof(struct pcap_device));
  device.dev_desc = pcap_open_dead(1, 128); /* link=1,snaplen=eth_header+my_iphdr+my_tlhdr */

  pcap_lookupnet(config.dev, &localnet, &netmask, errbuf);
  if (pcap_compile(device.dev_desc, &e->filter, value, 0, netmask) < 0) {
    Log(LOG_ERR, "ERROR ( %s ): malformed filter: %s\n", filename, pcap_geterr(device.dev_desc));
    return TRUE;
  }
  // bpf_dump(&e->filter, TRUE); 

  pcap_close(device.dev_desc);
  for (x = 0; e->func[x]; x++);
  e->func[x] = pretag_filter_handler;
  req->bpf_filter = TRUE;
  return FALSE;
}

int PT_map_v8agg_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int tmp; 
  int x = 0, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'v8agg' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  tmp = atoi(value);
  if (tmp < 1 || tmp > 14) {
    Log(LOG_ERR, "ERROR ( %s ): 'v8agg' need to be in the following range: 0 > value > 15. ", filename);
    return TRUE;
  }
  e->v8agg = tmp; 
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_v8agg_handler;

  return FALSE;
}

int PT_map_agent_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0;
  
  e->agent_id = atoi(value);
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_agent_id_handler;

  return FALSE;
}

int PT_map_sampling_rate_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int x = 0;

  e->sampling_rate = atoi(value);
  for (x = 0; e->func[x]; x++);
  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_sampling_rate_handler;

  return FALSE;
}

int PT_map_src_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int tmp;
  int x = 0;

  tmp = atoi(value);
  if (tmp < 1 || tmp > 65535) {
    Log(LOG_ERR, "ERROR ( %s ): 'src_as' need to be in the following range: 0 > value > 65536. ", filename);
    return TRUE;
  }

  e->src_as = tmp;
  for (x = 0; e->func[x]; x++);

  if ((config.nfacctd_as == NF_AS_NEW || config.acct_type == ACCT_PM) && config.networks_file) {
    req->bpf_filter = TRUE;
    e->func[x] = PM_pretag_src_as_handler;
    return FALSE;
  }
  else if (config.nfacctd_as == NF_AS_KEEP && config.acct_type == ACCT_NF) {
    e->func[x] = pretag_src_as_handler;
    return FALSE;
  }
  else if (config.nfacctd_as == NF_AS_KEEP && config.acct_type == ACCT_SF) {
    e->func[x] = SF_pretag_src_as_handler;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'src_as' requires either 'networks_file' or 'nf|sfacctd_as_new: false' to be specified. ", filename);

  return TRUE;
}

int PT_map_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req)
{
  int tmp;
  int x = 0;

  tmp = atoi(value);
  if (tmp < 1 || tmp > 65535) {
    Log(LOG_ERR, "ERROR ( %s ): 'dst_as' need to be in the following range: 0 > value > 65536. ", filename);
    return TRUE;
  }

  e->dst_as = tmp;
  for (x = 0; e->func[x]; x++);

  if ((config.nfacctd_as == NF_AS_NEW || config.acct_type == ACCT_PM) && config.networks_file) {
    req->bpf_filter = TRUE;
    e->func[x] = PM_pretag_dst_as_handler;
    return FALSE;
  }
  else if (config.nfacctd_as == NF_AS_KEEP && config.acct_type == ACCT_NF) {
    e->func[x] = pretag_dst_as_handler;
    return FALSE;
  }
  else if (config.nfacctd_as == NF_AS_KEEP && config.acct_type == ACCT_SF) {
    e->func[x] = SF_pretag_dst_as_handler;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'dst_as' requires either 'networks_file' or 'nf|sfacctd_as_new: false' to be specified. ", filename);

  return TRUE;
}

int pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t input = htons(entry->input);

  switch(hdr->version) {
  case 9:
    if (!memcmp(&input, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, tpl->tpl[NF9_INPUT_SNMP].len)) return FALSE;
    else return TRUE;
  case 8: 
    switch(hdr->aggregation) {
      case 1:
	if (input == ((struct struct_export_v8_1 *)pptrs->f_data)->input) return FALSE;
	else return TRUE;
      case 3:
	if (input == ((struct struct_export_v8_3 *)pptrs->f_data)->input) return FALSE;
	else return TRUE;
      case 5:
        if (input == ((struct struct_export_v8_5 *)pptrs->f_data)->input) return FALSE;
	else return TRUE;
      case 7:
	if (input == ((struct struct_export_v8_7 *)pptrs->f_data)->input) return FALSE;
	else return TRUE;
      case 8:
        if (input == ((struct struct_export_v8_8 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      case 9:
        if (input == ((struct struct_export_v8_9 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      case 10:
        if (input == ((struct struct_export_v8_10 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      case 11: 
        if (input == ((struct struct_export_v8_11 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      case 13:
        if (input == ((struct struct_export_v8_13 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      case 14:
        if (input == ((struct struct_export_v8_14 *)pptrs->f_data)->input) return FALSE;
        else return TRUE;
      default:
	return TRUE;
    }
  default:
    if (input == ((struct struct_export_v5 *)pptrs->f_data)->input) return FALSE;
    else return TRUE; 
  }
}

int pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t output = htons(entry->output);

  switch(hdr->version) {
  case 9:
    if (!memcmp(&output, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, tpl->tpl[NF9_OUTPUT_SNMP].len)) return FALSE;
    else return TRUE;
  case 8:
    switch(hdr->aggregation) {
      case 1:
        if (output == ((struct struct_export_v8_1 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 4:
        if (output == ((struct struct_export_v8_4 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 5:
        if (output == ((struct struct_export_v8_5 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 6:
        if (output == ((struct struct_export_v8_6 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 7:
        if (output == ((struct struct_export_v8_7 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 8:
        if (output == ((struct struct_export_v8_8 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 9:
        if (output == ((struct struct_export_v8_9 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 10:
        if (output == ((struct struct_export_v8_10 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 12:
        if (output == ((struct struct_export_v8_12 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 13:
        if (output == ((struct struct_export_v8_13 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      case 14:
        if (output == ((struct struct_export_v8_14 *)pptrs->f_data)->output) return FALSE;
        else return TRUE;
      default:
        return TRUE;
    }
  default:
    if (output == ((struct struct_export_v5 *)pptrs->f_data)->output) return FALSE;
    else return TRUE;
  }
}

int pretag_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    if (entry->nexthop.family == AF_INET) {
      if (!memcmp(&entry->nexthop.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_NEXT_HOP].off, tpl->tpl[NF9_IPV4_NEXT_HOP].len)) return FALSE;
    }
#if defined ENABLE_IPV6
    else if (entry->nexthop.family == AF_INET6) {
      if (!memcmp(&entry->nexthop.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_NEXT_HOP].off, tpl->tpl[NF9_IPV6_NEXT_HOP].len)) return FALSE;
    }
#endif
    else return TRUE;
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->nexthop.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return FALSE;
    else return TRUE;
  }
}

int pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 9:
    if (entry->bgp_nexthop.family == AF_INET) {
      if (!memcmp(&entry->bgp_nexthop.address.ipv4, pptrs->f_data+tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len)) return FALSE;
    }
#if defined ENABLE_IPV6
    else if (entry->nexthop.family == AF_INET6) {
      if (!memcmp(&entry->bgp_nexthop.address.ipv6, pptrs->f_data+tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len)) return FALSE;
    }
#endif
    else return TRUE;
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->bgp_nexthop.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return FALSE;
    else return TRUE;
  }
}

int pretag_engine_type_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_char value[4];

  switch(hdr->version) {
  case 9:
    memcpy(value, &((struct struct_header_v9 *)pptrs->f_data)->source_id, 4);
    if (entry->engine_type == (u_int8_t)value[1]) return FALSE;
    else return TRUE;
  case 8:
    if (entry->engine_type == ((struct struct_header_v8 *)pptrs->f_header)->engine_type) return FALSE;
    else return TRUE;
  case 5:
    if (entry->engine_type == ((struct struct_header_v5 *)pptrs->f_header)->engine_type) return FALSE;
    else return TRUE;
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_engine_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_char value[4];

  switch(hdr->version) {
  case 9:
    memcpy(value, &((struct struct_header_v9 *)pptrs->f_data)->source_id, 4);
    if (entry->engine_id == (u_int8_t)value[0]) return FALSE;
    else return TRUE;
  case 8:
    if (entry->engine_id == ((struct struct_header_v8 *)pptrs->f_header)->engine_id) return FALSE;
    else return TRUE;
  case 5:
    if (entry->engine_id == ((struct struct_header_v5 *)pptrs->f_header)->engine_id) return FALSE;
    else return TRUE;
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_filter_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (bpf_filter(entry->filter.bf_insns, pptrs->packet_ptr, pptrs->pkthdr->len, pptrs->pkthdr->caplen)) 
    return FALSE; /* matched filter */
  else return TRUE;
}

int pretag_v8agg_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;

  switch(hdr->version) {
  case 8:
    if (entry->v8agg == ((struct struct_header_v8 *)pptrs->f_header)->aggregation) return FALSE;
    else return TRUE;
  default:
    return TRUE; 
  }
}

int pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  switch(hdr->version) {
  case 9:
    if (tpl->tpl[NF9_SRC_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 2);
      asn32 = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_SRC_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 4);
      asn32 = ntohl(asn32);
    }
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      asn32 = ntohs(((struct struct_export_v8_1 *) pptrs->f_data)->src_as);
      break;
    case 3:
      asn32 = ntohs(((struct struct_export_v8_3 *) pptrs->f_data)->src_as);
      break;
    case 5:
      asn32 = ntohs(((struct struct_export_v8_5 *) pptrs->f_data)->src_as);
      break;
    case 9:
      asn32 = ntohs(((struct struct_export_v8_9 *) pptrs->f_data)->src_as);
      break;
    case 11:
      asn32 = ntohs(((struct struct_export_v8_11 *) pptrs->f_data)->src_as);
      break;
    case 13:
      asn32 = ntohs(((struct struct_export_v8_13 *) pptrs->f_data)->src_as);
      break;
    default:
      break;
    }
    break;
  default:
    asn32 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->src_as);
    break;
  }

  if (entry->src_as == asn32) return FALSE;
  else return TRUE;
}

int pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  switch(hdr->version) {
  case 9:
    if (tpl->tpl[NF9_DST_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 2);
      asn32 = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_DST_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 4);
      asn32 = ntohl(asn32);
    }
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      asn32 = ntohs(((struct struct_export_v8_1 *) pptrs->f_data)->dst_as);
      break;
    case 4:
      asn32 = ntohs(((struct struct_export_v8_4 *) pptrs->f_data)->dst_as);
      break;
    case 5:
      asn32 = ntohs(((struct struct_export_v8_5 *) pptrs->f_data)->dst_as);
      break;
    case 9:
      asn32 = ntohs(((struct struct_export_v8_9 *) pptrs->f_data)->dst_as);
      break;
    case 12:
      asn32 = ntohs(((struct struct_export_v8_12 *) pptrs->f_data)->dst_as);
      break;
    case 13:
      asn32 = ntohs(((struct struct_export_v8_13 *) pptrs->f_data)->dst_as);
      break;
    default:
      break;
    }
    break;
  default:
    asn32 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dst_as);
    break;
  }

  if (entry->dst_as == asn32) return FALSE;
  else return TRUE;
}

int pretag_id_handler(struct packet_ptrs *pptrs, void *id, void *e)
{
  struct id_entry *entry = e;

  int *tid = id;
  *tid = entry->id;
  return TRUE; /* cap */
}

int SF_pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->input == sample->inputPort) return FALSE;
  else return TRUE; 
}

int SF_pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->output == sample->outputPort) return FALSE;
  else return TRUE;
}

int SF_pretag_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->nexthop.family == AF_INET) {
    if (!memcmp(&entry->nexthop.address.ipv4, &sample->nextHop.address.ip_v4, 4)) return FALSE;
  }
#if defined ENABLE_IPV6
  else if (entry->nexthop.family == AF_INET6) {
    if (!memcmp(&entry->nexthop.address.ipv6, &sample->nextHop.address.ip_v6, IP6AddrSz)) return FALSE;
  }
#endif
  else return TRUE;
}

int SF_pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->bgp_nexthop.family == AF_INET) {
    if (!memcmp(&entry->bgp_nexthop.address.ipv4, &sample->bgp_nextHop.address.ip_v4, 4)) return FALSE;
  }
#if defined ENABLE_IPV6
  else if (entry->bgp_nexthop.family == AF_INET6) {
    if (!memcmp(&entry->bgp_nexthop.address.ipv6, &sample->bgp_nextHop.address.ip_v6, IP6AddrSz)) return FALSE;
  }
#endif
  else return TRUE;
}

int SF_pretag_agent_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->agent_id == sample->agentSubId) return FALSE;
  else return TRUE;
}

int SF_pretag_sampling_rate_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->sampling_rate == sample->meanSkipCount) return FALSE;
  else return TRUE;
}

int SF_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->src_as == sample->src_as) return FALSE;
  else return TRUE;
}

int SF_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->dst_as == sample->dst_as) return FALSE;
  else return TRUE;
}

int PM_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  u_int16_t res = search_pretag_src_as(&nt, &nc, pptrs);

  if (entry->src_as == res) return FALSE;
  else return TRUE;
}

int PM_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  u_int16_t res = search_pretag_dst_as(&nt, &nc, pptrs);

  if (entry->dst_as == res) return FALSE;
  else return TRUE;
}
