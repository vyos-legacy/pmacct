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

#define __NF_MAP_HANDLERS_C

#include "pmacct.h"
#include "nfacctd.h"
#include "nf_map_handlers.h"
#include "nfacctd-data.h"

int nf_map_id_handler(struct id_entry *e, char *value)
{
  e->id = atoi(value);
  if (!e->id) {
    Log(LOG_ERR, "ERROR: Agent ID '%d' is invalid (range: 0 > ID > 65535). ", e->id);
    return TRUE;
  } 

  return FALSE;
}

int nf_map_ip_handler(struct id_entry *e, char *value)
{
  if (!inet_aton(value, &e->agent_ip)) {
    Log(LOG_ERR, "ERROR: Bad IP address '%s'. ", value);
    return TRUE;
  }

  return FALSE;
}

int nf_map_input_handler(struct id_entry *e, char *value)
{
  int x = 0, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR: bad 'in' value: '%s'. ", value);
      return TRUE;
    }
    x++;
  }
  
  e->input = htons(atoi(value));
  for (x = 0; e->func[x]; x++);
  e->func[x] = nf_pktmap_input_handler; 
  return FALSE;
}

int nf_map_output_handler(struct id_entry *e, char *value)
{
  int x = 0, len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR: bad 'out' value: '%s'. ", value);
      return TRUE;
    }
    x++;
  }

  e->output = htons(atoi(value));
  for (x = 0; e->func[x]; x++);
  e->func[x] = nf_pktmap_output_handler;
  return FALSE;
}

int nf_pktmap_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  if (((struct id_entry *)e)->input == ((struct struct_export_v5 *)pptrs->f_data)->input) return FALSE;
  else return TRUE; 
}

int nf_pktmap_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  if (((struct id_entry *)e)->output == ((struct struct_export_v5 *)pptrs->f_data)->output) return FALSE;
  else return TRUE;
}

int nf_pktmap_id_handler(struct packet_ptrs *pptrs, void *id, void *e)
{
  int *tid = id;
  *tid = ((struct id_entry *)e)->id;
  return TRUE; /* cap */
}

