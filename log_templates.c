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

#define __LOG_TEMPLATES_C

#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"
#include "util.h"

struct template_entry *build_template(struct template_header *th)
{
  struct template_entry *ptr, *base;
  struct db_cache dummy;
  u_char *te;
  u_int16_t tot_size = 0;

  th->num = 13;

  te = malloc(th->num*sizeof(struct template_entry));  
  memset(te, 0, th->num*sizeof(struct template_entry));
  base = (struct template_entry *) te;
  ptr = base;

  ptr->tag = COUNT_DST_MAC;
  ptr->size = sizeof(dummy.eth_dhost);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_MAC;
  ptr->size = sizeof(dummy.eth_shost);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_VLAN;
  ptr->size = sizeof(dummy.vlan_id);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_HOST;
  ptr->size = sizeof(dummy.src_ip);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_DST_HOST;
  ptr->size = sizeof(dummy.dst_ip);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_PORT;
  ptr->size = sizeof(dummy.src_port);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_DST_PORT;
  ptr->size = sizeof(dummy.dst_port);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_IP_TOS; 
  ptr->size = sizeof(dummy.tos);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_IP_PROTO;
  ptr->size = sizeof(dummy.proto);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_ID;
  ptr->size = sizeof(dummy.id);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = BYTES;
  ptr->size = sizeof(dummy.bytes_counter);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = PACKETS;
  ptr->size = sizeof(dummy.packet_counter);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = TIMESTAMP;
  ptr->size = sizeof(dummy.basetime);
  tot_size += ptr->size;

  th->magic = htonl(TH_MAGIC);
  th->num = htons(th->num);
  th->sz = htons(tot_size);

  return base;
}

void set_template_funcs(struct template_header *th, struct template_entry *head)
{
  struct template_entry *te;
  int cnt;

  memset(&template_funcs, 0, sizeof(template_funcs));

  for (te = head, cnt = 0; cnt < ntohs(th->num); cnt++, te++) {
    switch (te->tag) {
    case COUNT_SRC_MAC:
      template_funcs[cnt] = TPL_push_src_mac;
      break;
    case COUNT_DST_MAC:
      template_funcs[cnt] = TPL_push_dst_mac; 
      break;
    case COUNT_VLAN:
      template_funcs[cnt] = TPL_push_vlan;
      break;
    case COUNT_SRC_HOST:
      template_funcs[cnt] = TPL_push_src_ip;
      break;
    case COUNT_DST_HOST:
      template_funcs[cnt] = TPL_push_dst_ip;
      break;
    case COUNT_SRC_PORT:
      template_funcs[cnt] = TPL_push_src_port;
      break;
    case COUNT_DST_PORT:
      template_funcs[cnt] = TPL_push_dst_port;
      break;
    case COUNT_IP_TOS: 
      template_funcs[cnt] = TPL_push_tos;
      break;
    case COUNT_IP_PROTO:
      template_funcs[cnt] = TPL_push_proto;
      break;
    case COUNT_ID:
      template_funcs[cnt] = TPL_push_id;
      break;
    case BYTES:
      template_funcs[cnt] = TPL_push_bytes_counter;
      break;
    case PACKETS:
      template_funcs[cnt] = TPL_push_packet_counter;
      break;
    case TIMESTAMP:
      template_funcs[cnt] = TPL_push_timestamp;
      break;
    default:
      template_funcs[cnt] = NULL;
      break;
    }
  }
}

u_int16_t TPL_push(u_char *dst, const struct db_cache *src)
{
  u_char *ptr = dst;
  int cnt = 0;

  while (template_funcs[cnt]) {
    (*template_funcs[cnt])(&ptr, src);
    cnt++;
  }

  return ptr-dst;
}

void TPL_push_src_mac(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->eth_shost);

  memcpy(*dst, src->eth_shost, size); 
  *dst += size;
}	

void TPL_push_dst_mac(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->eth_dhost);

  memcpy(*dst, src->eth_dhost, size);
  *dst += size;
}

void TPL_push_vlan(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->vlan_id);

  memcpy(*dst, &src->vlan_id, size);
  *dst += size;
}

void TPL_push_src_ip(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->src_ip);

  memcpy(*dst, &src->src_ip, size);
  *dst += size;
}

void TPL_push_dst_ip(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->dst_ip);

  memcpy(*dst, &src->dst_ip, size);
  *dst += size;
}

void TPL_push_src_port(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->src_port);

  memcpy(*dst, &src->src_port, size);
  *dst += size;
}

void TPL_push_dst_port(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->dst_port);

  memcpy(*dst, &src->dst_port, size);
  *dst += size;
}

void TPL_push_tos(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->tos);

  memcpy(*dst, &src->tos, size);
  *dst += size;
}

void TPL_push_proto(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->proto);

  memcpy(*dst, &src->proto, size);
  *dst += size;
}

void TPL_push_id(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->id);

  memcpy(*dst, &src->id, size);
  *dst += size;
}

void TPL_push_bytes_counter(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->bytes_counter);

  memcpy(*dst, &src->bytes_counter, size);
  *dst += size;
}

void TPL_push_packet_counter(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->packet_counter);

  memcpy(*dst, &src->packet_counter, size);
  *dst += size;
}

void TPL_push_timestamp(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->basetime);

  memcpy(*dst, &src->basetime, size);
  *dst += size;
}

void TPL_pop(u_char *src, struct db_cache *dst, struct template_header *th, u_char *te)
{
  struct template_entry *teptr = (struct template_entry *)te;
  u_char *ptr = src;
  int cnt = 0, tot_sz = 0, sz = 0;

  for (; cnt < th->num; cnt++, ptr += sz, tot_sz += sz, teptr++) { 
    if (tot_sz > th->sz) {
      printf("ERROR: malformed template entry. Size mismatch. Exiting.\n");
      exit(1); 
    }
    sz = teptr->size;
    
    switch (teptr->tag) {
    case COUNT_SRC_MAC:
      memcpy(&dst->eth_shost, ptr, sz);
      break;
    case COUNT_DST_MAC:
      memcpy(&dst->eth_dhost, ptr, sz);
      break;
    case COUNT_VLAN:
      memcpy(&dst->vlan_id, ptr, sz);
      break;
    case COUNT_SRC_HOST:
      if (sz == 4) {
	/* legacy IP addresses */
	memcpy(&dst->src_ip.address.ipv4, ptr, sz);
	dst->src_ip.family = AF_INET;
	break;
      } 
      memcpy(&dst->src_ip, ptr, sz);
      break;
    case COUNT_DST_HOST:
      if (sz == 4) {
        /* legacy IP addresses */
	memcpy(&dst->dst_ip.address.ipv4, ptr, sz);
	dst->dst_ip.family = AF_INET;
	break;
      }
      memcpy(&dst->dst_ip, ptr, sz);
      break;
    case COUNT_SRC_PORT:
      memcpy(&dst->src_port, ptr, sz);
      break;
    case COUNT_DST_PORT:
      memcpy(&dst->dst_port, ptr, sz);
      break;
    case COUNT_IP_TOS:
      memcpy(&dst->tos, ptr, sz);
      break;
    case COUNT_IP_PROTO:
      memcpy(&dst->proto, ptr, sz);
      break;
    case COUNT_ID:
      memcpy(&dst->id, ptr, sz);
      break;
    case BYTES:
      memcpy(&dst->bytes_counter, ptr, sz);
      break;
    case PACKETS:
      memcpy(&dst->packet_counter, ptr, sz);
      break;
    case TIMESTAMP:
      memcpy(&dst->basetime, ptr, sz);
      break;
    default:
      printf("ERROR: template entry not supported: '%d'\n", teptr->tag);
      exit(1); 
    }
  }
}

void TPL_check_sizes(struct template_header *th, struct db_cache *elem, u_char *te)
{
  struct template_entry *teptr = (struct template_entry *) te;
  int cnt = 0;

  for (; cnt < th->num; cnt++, teptr++) {
    switch (teptr->tag) {
    case COUNT_SRC_MAC:
      if (teptr->size > sizeof(elem->eth_shost)) goto exit_lane;
      break;
    case COUNT_DST_MAC:
      if (teptr->size > sizeof(elem->eth_dhost)) goto exit_lane;
      break;
    case COUNT_VLAN:
      if (teptr->size > sizeof(elem->vlan_id)) goto exit_lane;
      break;
    case COUNT_SRC_HOST:
      if (teptr->size > sizeof(elem->src_ip)) goto exit_lane;
      break;
    case COUNT_DST_HOST:
      if (teptr->size > sizeof(elem->dst_ip)) goto exit_lane;
      break;
    case COUNT_SRC_PORT:
      if (teptr->size > sizeof(elem->src_port)) goto exit_lane;
      break;
    case COUNT_DST_PORT:
      if (teptr->size > sizeof(elem->dst_port)) goto exit_lane;
      break;
    case COUNT_IP_TOS:
      if (teptr->size > sizeof(elem->tos)) goto exit_lane;
      break;
    case COUNT_IP_PROTO:
      if (teptr->size > sizeof(elem->proto)) goto exit_lane;
      break;
    case COUNT_ID:
      if (teptr->size > sizeof(elem->id)) goto exit_lane;
      break;
    case BYTES:
      if (teptr->size > sizeof(elem->bytes_counter)) goto exit_lane;
      break;
    case PACKETS:
      if (teptr->size > sizeof(elem->packet_counter)) goto exit_lane;
      break;
    case TIMESTAMP:
      if (teptr->size > sizeof(elem->basetime)) goto exit_lane;
      break;
    default:
      printf("ERROR: template entry not supported: '%d'\n", teptr->tag);
      exit(1);
    exit_lane:
      printf("ERROR: template entry '%d' is too big. Exiting.\n", teptr->tag);
      exit(1);
    }
  }
}
