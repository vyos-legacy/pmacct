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
#include "util.h"

static char fake_mac[] = "0:0:0:0:0:0";
static char fake_host[] = "0.0.0.0";

/* Functions */
void count_src_mac_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  char *ptr;

  ptr = (char *)ether_ntoa(cache_elem->eth_shost);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_mac_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  char *ptr;

  ptr = (char *)ether_ntoa(cache_elem->eth_dhost);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_vlan_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->vlan_id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->vlan_id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_host_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  char *ptr;

  ptr = inet_ntoa(cache_elem->src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_src_host_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->src_ip.s_addr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->src_ip.s_addr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  char *ptr;

   ptr = inet_ntoa(cache_elem->dst_ip);
   snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
   snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
   *ptr_where += strlen(*ptr_where);
   *ptr_values += strlen(*ptr_values);
}

void PG_count_dst_host_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->dst_ip.s_addr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->dst_ip.s_addr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_port_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_port_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void MY_count_ip_proto_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  if (cache_elem->proto <= protocols_number) {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, _protocols[cache_elem->proto].name);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, _protocols[cache_elem->proto].name);
  }
  else {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->proto);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->proto);
  }
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_ip_proto_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->proto);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->proto);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->basetime);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_timestamp_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time(NULL), cache_elem->basetime);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_id_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

/* Fake handlers next */ 
void fake_mac_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_mac);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_mac);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_host_handler(const struct db_cache *cache_elem, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_host);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_host);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
