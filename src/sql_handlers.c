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

#define __SQL_HANDLERS_C

/*
  PG_* functions are used only by PostgreSQL plugin;
  MY_* functions are used only by MySQL plugin;
  count_* functions are used by more than one plugin;
  fake_* functions are used to supply static zero-filled values;
*/ 

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "ip_flow.h"
#include "classifier.h"
#include "util.h"

static const char fake_mac[] = "0:0:0:0:0:0";
static const char fake_host[] = "0.0.0.0";
static const char fake_as[] = "0";

/* Functions */
#if defined (HAVE_L2)
void count_src_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[17];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(&ubuf, &cache_elem->primitives.eth_shost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[17];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(ubuf, &cache_elem->primitives.eth_dhost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_vlan_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.vlan_id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.vlan_id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif

void count_src_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_ip_tos_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.tos);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.tos);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}


void MY_count_ip_proto_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  if (cache_elem->primitives.proto <= protocols_number) {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, _protocols[cache_elem->primitives.proto].name);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, _protocols[cache_elem->primitives.proto].name);
  }
  else {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.proto);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.proto);
  }
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_ip_proto_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.proto);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.proto);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, idata->now, cache_elem->basetime);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_id_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_class_id_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char buf[MAX_PROTOCOL_LEN+1];

  memset(buf, 0, MAX_PROTOCOL_LEN+1);
  if (cache_elem->primitives.class && class[cache_elem->primitives.class-1].id) {
    strlcpy(buf, class[cache_elem->primitives.class-1].protocol, MAX_PROTOCOL_LEN);
    buf[sizeof(buf)-1] = '\0';
  }
  else strlcpy(buf, "unknown", MAX_PROTOCOL_LEN);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, buf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, buf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

/* Fake handlers next */ 
void fake_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_mac);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_mac);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_host);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_host);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
