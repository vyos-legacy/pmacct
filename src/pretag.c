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

/* defines */
#define __PRETAG_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pretag-data.h"

void load_id_file(int acct_type, char *filename, struct id_table *t, struct plugin_requests *req)
{
  struct id_table tmp;
  struct id_entry *ptr;
  FILE *file;
  char buf[SRVBUFLEN];
  int v4_num = 0, x, tot_lines = 0, err, index;
  struct stat st;

#if defined ENABLE_IPV6
  int v6_num = 0;
#endif

  /* parsing engine vars */
  char *start, *key = NULL, *value = NULL;
  int len;

  memset(&st, 0, sizeof(st));

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR: Pre-Tagging map '%s' not found.\n", filename);
      goto handle_error;
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
          if (!check_not_valid_char(filename, buf, '|')) {
            mark_columns(buf);
            trim_all_spaces(buf);
	    strip_quotes(buf);

            memset(&tmp.e[tmp.num], 0, sizeof(struct id_entry));
            err = FALSE; key = NULL; value = NULL;
            start = buf;
            len = strlen(buf);

            for (x = 0; x <= len; x++) {
              if (buf[x] == '=') {
                if (start == &buf[x]) continue;
                if (!key) {
                  buf[x] = '\0';
		  key = start;
                  x++;
                  start = &buf[x];
		}
              }
              if ((buf[x] == '|') || (buf[x] == '\0')) {
                if (start == &buf[x]) continue;
                buf[x] = '\0';
                if (value || !key) {
                  Log(LOG_ERR, "ERROR ( %s ): malformed line %d. Ignored.\n", filename, tot_lines);
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
                    err = (*map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req);
                    break;
                  }
                  else err = E_NOTFOUND; /* key not found */
                }
                if (err) {
                  if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s ): unknown key '%s' at line %d. Ignored.\n", filename, key, tot_lines);
                  else Log(LOG_ERR, "Line %d ignored.\n", tot_lines);
                  break; 
                }
                key = NULL; value = NULL;
              }
            }
            /* verifying errors and required fields */
	    if (acct_type == ACCT_NF || acct_type == ACCT_SF) {
              if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].agent_ip.family) {
                int j;

                for (j = 0; tmp.e[tmp.num].func[j]; j++);
                tmp.e[tmp.num].func[j] = pretag_id_handler;
	        if (tmp.e[tmp.num].agent_ip.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
	        else if (tmp.e[tmp.num].agent_ip.family == AF_INET6) v6_num++;
#endif
                tmp.num++;
              }
	      /* if any required field is missing and other errors have been signalled
	         before we will trap an error message */
	      else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].agent_ip.family) && !err)
	        Log(LOG_ERR, "ERROR ( %s ): required key missing at line: %d. Required keys are: 'id', 'ip'.\n", filename, tot_lines); 
	    }
	    else if (acct_type == ACCT_PM) {
	      if (tmp.e[tmp.num].agent_ip.family)
		Log(LOG_ERR, "ERROR ( %s ): key 'ip' not applicable here. Invalid line: %d.\n", filename, tot_lines);
	      else if (!err && tmp.e[tmp.num].id) {
                int j;

		for (j = 0; tmp.e[tmp.num].func[j]; j++);
		tmp.e[tmp.num].agent_ip.family = AF_INET; /* we emulate a dummy '0.0.0.0' IPv4 address */
		tmp.e[tmp.num].func[j] = pretag_id_handler;
		v4_num++; tmp.num++;
	      } 
	    }
          }
          else Log(LOG_ERR, "ERROR ( %s ): malformed line: %d. Ignored.\n", filename, tot_lines);
        }
      }
    }
    fclose(file);

    stat(filename, &st);
    t->timestamp = st.st_mtime;

    /* second stage: rearranging things in a sorted memory table
       we will break the process into two parts: IPv4 and IPv6 */

    x = 0;
    t->num = tmp.num;
    t->ipv4_num = v4_num; 
    t->ipv4_base = &t->e[x];
    while (v4_num) {
      for (index = 0, ptr = NULL; index < tmp.num; index++) {
        if (!ptr) {
          if (tmp.e[index].id && tmp.e[index].agent_ip.family == AF_INET) ptr = &tmp.e[index];
        }
        else {
	  if (tmp.e[index].id && (tmp.e[index].agent_ip.family == AF_INET)) { 
            if (ptr->agent_ip.address.ipv4.s_addr > tmp.e[index].agent_ip.address.ipv4.s_addr)
	      ptr = &tmp.e[index];
	  }
        }
      }
      memcpy(&t->e[x], ptr, sizeof(struct id_entry));
      ptr->id = FALSE;
      v4_num--; x++;
    }
#if defined ENABLE_IPV6
    t->ipv6_num = v6_num;
    t->ipv6_base = &t->e[x];
    while (v6_num) {
      for (index = 0, ptr = NULL; index < tmp.num; index++) {
        if (!ptr) {
          if (tmp.e[index].id && tmp.e[index].agent_ip.family == AF_INET6) ptr = &tmp.e[index];
        }
        else {
          if (tmp.e[index].id && (tmp.e[index].agent_ip.family == AF_INET6)) {
            if (ip6_addr_cmp(&ptr->agent_ip.address.ipv6, &tmp.e[index].agent_ip.address.ipv6) > 0)
              ptr = &tmp.e[index];
          }
        }
      }
      memcpy(&t->e[x], ptr, sizeof(struct id_entry));
      ptr->id = FALSE;
      v6_num--; x++;
    }
#endif
  }

  return;

  handle_error:
  if (t->timestamp) {
    Log(LOG_WARNING, "WARN: Rolling back the old Pre-Tagging Map.\n");

    /* we update the timestamp to avoid loops */
    stat(filename, &st);
    t->timestamp = st.st_mtime;
  }
  else exit_all(1);
}

