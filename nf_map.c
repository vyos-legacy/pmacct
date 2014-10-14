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

/* defines */
#define __NFACCTD_MAP_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "nf_map_handlers.h"
#include "nfacctd-data.h"

void load_id_file(char *filename, struct id_table *t)
{
  struct id_table tmp;
  struct id_entry *ptr;
  FILE *file;
  char buf[SRVBUFLEN];
  int to_sort, x, tot_lines = 0, err, index;

  /* parsing engine vars */
  char *start, *key = NULL, *value = NULL;
  int len;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR: Agent ID file '%s' not found\n", filename);
      exit(1);
    }

    memset(t, 0, sizeof(struct id_table));
    memset(&tmp, 0, sizeof(struct id_table));

    /* first stage: reading Agent ID file and arranging it in a temporary memory table */
    while (!feof(file)) {
      tot_lines++;
      if (tmp.num >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) {
        if (!iscomment(buf) && !isblankline(buf)) {
          if (!check_not_valid_char(buf, ';')) {
            mark_columns(buf);
            trim_all_spaces(buf);

            memset(&tmp.e[tmp.num], 0, sizeof(struct id_entry));
            err = FALSE; key = NULL; value = NULL;
            start = buf;
            len = strlen(buf);

            for (x = 0; x <= len; x++) {
              if (buf[x] == '=') {
                if (start == &buf[x]) continue;
                buf[x] = '\0';
                if (key) {
                  Log(LOG_ERR, "ERROR: %s: malformed line %d. Ignored.\n", filename, tot_lines);
                  err = TRUE;
                  break;
                }
                else key = start;
                x++;
                start = &buf[x];
              }
              if ((buf[x] == ';') || (buf[x] == '\0')) {
                if (start == &buf[x]) continue;
                buf[x] = '\0';
                if (value || !key) {
                  Log(LOG_ERR, "ERROR: %s: malformed line %d. Ignored.\n", filename, tot_lines);
                  err = TRUE;
                  break;
                }
                else value = start;
                x++;
                start = &buf[x];
              }

              if (key && value) {
                int dindex; /* dictionary index */

                for (dindex = 0; strcmp(map_dictionary[dindex].key, ""); dindex++) {
                  if (!strcmp(map_dictionary[dindex].key, key)) {
                    err = (*map_dictionary[dindex].func)(&tmp.e[tmp.num], value);
                    break;
                  }
                  else err = E_NOTFOUND; /* key not found */
                }
                if (err) {
                  if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR: %s: unknown key '%s' at line %d. Ignored.\n", filename, key, tot_lines);
                  else Log(LOG_ERR, "%s: line %d ignored.\n", filename, tot_lines);
                  break; 
                }
                key = NULL; value = NULL;
              }
            }
            /* verifying errors and required fields */
            if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].agent_ip.s_addr) {
              int j;

              for (j = 0; tmp.e[tmp.num].func[j]; j++);
              tmp.e[tmp.num].func[j] = nf_pktmap_id_handler;
              tmp.num++;
            }
	    /* if a required is missing and any other error have been signalled before
	       we will trap an error message */
	    else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].agent_ip.s_addr) && !err)
	      Log(LOG_ERR, "ERROR: required key missing at line: %d. Required keys are: 'id', 'ip'.\n", tot_lines); 
          }
          else Log(LOG_ERR, "%s: malformed line %d. Ignored.\n", filename, tot_lines);
        }
      }
    }
    fclose(file);

    // for (x = 0; x < tmp.num; x++) {
    //  printf("id: %d, ip: %s, in: %d\n", tmp.e[x].id, inet_ntoa(tmp.e[x].agent_ip), tmp.e[x].input);
    // }

    /* second stage: rearranging things in a sorted memory table */
    to_sort = tmp.num;
    t->num = tmp.num;
    x = 0;
    while (to_sort) {
      for (index = 0, ptr = NULL; index < tmp.num; index++) {
        if (!ptr) {
          if (tmp.e[index].id) ptr = &tmp.e[index];
        }
        else {
          if ((ptr->agent_ip.s_addr > tmp.e[index].agent_ip.s_addr) && tmp.e[index].id) ptr = &tmp.e[index];
        }
      }
      memcpy(&t->e[x], ptr, sizeof(struct id_entry));
      ptr->id = FALSE;
      to_sort--; x++;
    }
  }
}

