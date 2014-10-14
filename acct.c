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

#define __ACCT_C

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"
#include "crc32.c"

/* functions */
struct acc *search_accounting_structure(struct pkt_primitives *addr)
{
  struct acc *elem_acc;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives); 

  hash = cache_crc32((unsigned char *)addr, pp_size);
  pos = hash % config.buckets;

  if (config.debug) Log(LOG_DEBUG, "Bucket: %u\n", pos);

  elem_acc = (struct acc *) a;
  elem_acc += pos;  
  
  while (elem_acc) {
    if (elem_acc->signature == hash) {
      if (!memcmp(elem_acc, addr, sizeof(struct pkt_primitives))) return elem_acc;
    }
    elem_acc = elem_acc->next;
  } 

  return NULL;
}


void insert_accounting_structure(struct pkt_data *data)
{
  struct pkt_primitives *addr = &data->primitives;
  struct acc *elem_acc;
  unsigned char *elem, *new_elem;
  int solved = FALSE;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives);

  elem = a;

  hash = cache_crc32((unsigned char *)addr, pp_size);
  pos = hash % config.buckets;
      
  if (config.debug) Log(LOG_DEBUG, "Bucket: %u\n", pos);
  /* 
     1st stage: compare data with last used element;
     2nd stage: compare data with elements in the table, following chains
  */
  if (lru_elem_ptr[pos]) {
    elem_acc = lru_elem_ptr[pos];
    if (elem_acc->signature == hash) {
      if (memcmp(elem_acc, addr, sizeof(struct pkt_primitives)) == 0) {
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += ntohl(data->pkt_num);
        elem_acc->bytes_counter += ntohl(data->pkt_len);
        return;
      }
    }
  }

  elem_acc = (struct acc *) elem;
  elem_acc += pos;

  while (solved == FALSE) {
    if (elem_acc->signature == hash) {
      if (memcmp(elem_acc, addr, sizeof(struct pkt_primitives)) == 0) {
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += ntohl(data->pkt_num);
        elem_acc->bytes_counter += ntohl(data->pkt_len);
        lru_elem_ptr[config.buckets] = elem_acc;
        return;
      }
    }
    if (!elem_acc->bytes_counter && !elem_acc->packet_counter) { /* hmmm */
      if (elem_acc->reset_flag) elem_acc->reset_flag = FALSE; 
      memcpy(elem_acc, addr, sizeof(struct pkt_primitives));
      elem_acc->packet_counter += ntohl(data->pkt_num);
      elem_acc->bytes_counter += ntohl(data->pkt_len);
      elem_acc->signature = hash;
      lru_elem_ptr[config.buckets] = elem_acc;
      return;
    }

    /* Handling collisions */
    else if (elem_acc->next != NULL) {
      if (config.debug) Log(LOG_DEBUG, "Walking through the collision-chain for this bucket\n");
      elem_acc = elem_acc->next;
      solved = FALSE;
    }
    else if (elem_acc->next == NULL) {
      /* We have to know if there is enough space for a new element;
         if not we are losing informations; conservative approach */
      if (no_more_space) return;

      /* We have to allocate new space for this address */
      if (config.debug) Log(LOG_DEBUG, "Creating new element in this bucket\n");

      if (current_pool->space_left >= sizeof(struct acc)) {
        new_elem = current_pool->ptr;
	current_pool->space_left -= sizeof(struct acc);
	current_pool->ptr += sizeof(struct acc);
      }
      else {
        current_pool = request_memory_pool(config.memory_pool_size); 
	if (current_pool == NULL) {
          Log(LOG_WARNING, "WARN: unable to allocate more memory pools, clear stats manually!\n");
	  no_more_space = TRUE;
	  return;
        }
        else {
          new_elem = current_pool->ptr;
          current_pool->space_left -= sizeof(struct acc);
          current_pool->ptr += sizeof(struct acc);
	}
      }

      elem_acc->next = (struct acc *) new_elem;
      elem_acc = (struct acc *) new_elem;
      memcpy(elem_acc, addr, sizeof(struct pkt_primitives));
      elem_acc->packet_counter += ntohl(data->pkt_num);
      elem_acc->bytes_counter += ntohl(data->pkt_len);
      elem_acc->signature = hash;
      elem_acc->next = NULL;
      lru_elem_ptr[config.buckets] = elem_acc;
      return;
    }
  }
}

void set_reset_flag(struct acc *elem)
{
  elem->reset_flag = TRUE;
}

void reset_counters(struct acc *elem)
{
  elem->reset_flag = FALSE;
  elem->packet_counter = 0;
  elem->bytes_counter = 0;
}
