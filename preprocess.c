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

#define __PREPROCESS_C

#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"
#include "util.h"

void set_preprocess_funcs(char *string, struct preprocess *prep)
{
  char *token, *sep, *key, *value;
  int j = 0;

  memset(preprocess_funcs, 0, sizeof(preprocess_funcs));
  memset(prep, 0, sizeof(struct preprocess));

  if (!string) return;

  trim_all_spaces(string);

  while (token = extract_token(&string, ',')) {
    sep = strchr(token, '=');
    if (!sep) {
      Log(LOG_WARNING, "WARN: Malformed preprocess string. Discarded.\n");
      return; 
    }
    else {
      key = token;
      *sep = '\0';
      value = sep+1;
    } 

    if (!strcmp(key, "qnum")) {
      prep->qnum = atoi(value);
      if (!prep->qnum) Log(LOG_WARNING, "WARN: preprocess: Invalid 'qnum' value.\n");
    }
    else if (!strcmp(key, "minp")) {
      prep->minp = atoi(value);
      if (!prep->minp) Log(LOG_WARNING, "WARN: preprocess: Invalid 'minp' value.\n");
    }
    else if (!strcmp(key, "minb")) {
      prep->minb = atoi(value);
      if (!prep->minb) Log(LOG_WARNING, "WARN: preprocess: Invalid 'minb' value.\n");
    }
    else if (!strcmp(key, "recover")) {
      prep->recover = atoi(value);
      if (!prep->recover) Log(LOG_WARNING, "WARN: preprocess: Invalid 'recover' value.\n");
    }
    else Log(LOG_ERR, "ERROR: Invalid preprocess key: '%s'. Ignored.\n", key);
  }

  /* Post checks: almost one check should have been specified */
  if ((!prep->minp) && (!prep->minb)) {
    Log(LOG_ERR, "ERROR: 'sql_preprocess' does not contain any check. Ignored.\n"); 
    return;
  } 

  /* 1st step: insert conditionals */
  if (prep->qnum) {
    preprocess_funcs[j] = cond_qnum;
    j++;
  }

  /* 2nd step: insert checks */
  if (prep->minp) {
    preprocess_funcs[j] = check_minp;
    j++;
  } 

  if (prep->minb) {
    preprocess_funcs[j] = check_minb;
    j++;
  }
}

int cond_qnum(struct db_cache *queue[], int *num)
{
  if (*num > prep.qnum) return FALSE; 
  else return TRUE;
}

int check_minp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter < prep.minp) {
      if (prep.recover) queue[x]->valid = -1;
      else queue[x]->valid = 0;
    }
  }  

  return FALSE;
}

int check_minb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter < prep.minb) {
      if (prep.recover) queue[x]->valid = -1;
      else queue[x]->valid = 0;
    }
  }

  return FALSE;
}
