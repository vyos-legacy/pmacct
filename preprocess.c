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
      Log(LOG_WARNING, "WARN ( %s/%s ): Malformed preprocess string. Discarded.\n", config.name, config.type);
      return; 
    }
    else {
      key = token;
      *sep = '\0';
      value = sep+1;
    } 

    if (!strcmp(key, "qnum")) {
      prep->qnum = atoi(value);
      if (!prep->qnum) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'qnum' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minp")) {
      prep->minp = atoi(value);
      if (!prep->minp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minf")) {
      prep->minf = atoi(value);
      if (!prep->minf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minb")) {
      prep->minb = atoi(value);
      if (!prep->minb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxp")) {
      prep->maxp = atoi(value);
      if (!prep->maxp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxf")) {
      prep->maxf = atoi(value);
      if (!prep->maxf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxb")) {
      prep->maxb = atoi(value);
      if (!prep->maxb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxbpp")) {
      prep->maxbpp = atoi(value);
      if (!prep->maxbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxppf")) {
      prep->maxppf = atoi(value);
      if (!prep->maxppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxppf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minbpp")) {
      prep->minbpp = atoi(value);
      if (!prep->minbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minppf")) {
      prep->minppf = atoi(value);
      if (!prep->minppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minppf' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "recover")) {
      prep->recover = atoi(value);
      if (!prep->recover) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'recover' value.\n", config.name, config.type);
    }
    else Log(LOG_ERR, "ERROR ( %s/%s ): Invalid preprocess key: '%s'. Ignored.\n", config.name, config.type, key);
  }

  /* Post checks: almost one check should have been specified */
  if ((!prep->minp) && (!prep->minb) && (!prep->minf) &&
      (!prep->maxp) && (!prep->maxb) && (!prep->maxf) &&
      (!prep->maxbpp) && (!prep->maxppf) && (!prep->minbpp) &&
      (!prep->minppf)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'sql_preprocess' does not contain any check. Ignored.\n", config.name, config.type); 
    return;
  } 

  /* 1st step: insert conditionals */
  if (prep->qnum) {
    preprocess_funcs[j] = cond_qnum;
    j++;
  }

  /* 2nd step: full-cache invalidation; each of the following
     checks will re-validate matching entries */
  preprocess_funcs[j] = mandatory_invalidate;
  j++;

  /* 3rd step: insert checks */
  if (prep->minp) {
    preprocess_funcs[j] = check_minp;
    prep->num++;
    j++;
  } 

  if (prep->minf) {
    preprocess_funcs[j] = check_minf;
    prep->num++;
    j++;
  }

  if (prep->minb) {
    preprocess_funcs[j] = check_minb;
    prep->num++;
    j++;
  }

  if (prep->maxp) {
    preprocess_funcs[j] = check_maxp;
    prep->num++;
    j++;
  }

  if (prep->maxf) {
    preprocess_funcs[j] = check_maxf;
    prep->num++;
    j++;
  }

  if (prep->maxb) {
    preprocess_funcs[j] = check_maxb;
    prep->num++;
    j++;
  }

  if (prep->maxbpp) {
    preprocess_funcs[j] = check_maxbpp;
    prep->num++;
    j++;
  }

  if (prep->maxppf) {
    preprocess_funcs[j] = check_maxppf;
    prep->num++;
    j++;
  }

  if (prep->minbpp) {
    preprocess_funcs[j] = check_minbpp;
    prep->num++;
    j++;
  }

  if (prep->minppf) {
    preprocess_funcs[j] = check_minppf;
    prep->num++;
    j++;
  }

  /* 
     4th and final step: check points:
     - if in 'any' mode, any entry with 'points >= 1' is valid
     - if in 'all' mode, any entry with 'points == number of conditions' is valid 
  */
  preprocess_funcs[j] = mandatory_validate;
  j++;
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
    if (queue[x]->packet_counter >= prep.minp) queue[x]->valid++;
  }  

  return FALSE;
}

int check_minb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter >= prep.minb) queue[x]->valid++; 
  }

  return FALSE;
}

int check_minf(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->flows_counter >= prep.minf) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter < prep.maxp) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter < prep.maxb) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxf(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->flows_counter < prep.maxf) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxbpp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter/queue[x]->packet_counter < prep.maxbpp) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxppf(struct db_cache *queue[], int *num)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter/queue[x]->flows_counter < prep.maxppf) queue[x]->valid++;
  }

  return FALSE;
}

int check_minbpp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter/queue[x]->packet_counter >= prep.minbpp) queue[x]->valid++; 
  }

  return FALSE;
}

int check_minppf(struct db_cache *queue[], int *num)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter/queue[x]->flows_counter >= prep.minppf) queue[x]->valid++; 
  }

  return FALSE;
}

int mandatory_invalidate(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) queue[x]->valid = 0; 

  return FALSE;
}

/*
  - 'sql_preprocess_type == 0' means match 'any' of the checks
  - 'sql_preprocess_type == 1' means match 'all' checks
*/
int mandatory_validate(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (config.sql_preprocess_type == 1 && queue[x]->valid < prep.num) queue[x]->valid = 0; 
    if ((!queue[x]->valid) && prep.recover) queue[x]->valid = -1;
  }

  return FALSE;
}
