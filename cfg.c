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

#define __CFG_C

/* includes */
#include "pmacct.h"
#include "plugin_hooks.h"
#include "pmacct-data.h"
#include "pkt_handlers.h"

/* evaluate_configuration() handles all supported configuration
   keys and inserts them in configuration structure of plugins */
void evaluate_configuration(int rows)
{
  char *key, *value, *name, *delim;
  int index = 0, dindex, valid_line, key_found = 0, res;

  while (index < rows) {
    if (*cfg[index] == '\0') valid_line = FALSE;
    else valid_line = TRUE; 

    if (valid_line) {
      /* splitting key, value and name */
      delim = strchr(cfg[index], ':');
      *delim = '\0';
      key = cfg[index];
      value = delim+1;

      delim = strchr(key, '[');
      if (delim) {
        *delim = '\0';
        name = delim+1;
        delim = strchr(name, ']');
        *delim = '\0';
      }
      else name = NULL;

      /* parsing keys */
      for (dindex = 0; strcmp(dictionary[dindex].key, ""); dindex++) {
        if (!strcmp(dictionary[dindex].key, key)) {
	  res = FALSE;
          if ((*dictionary[dindex].func)) {
	    res = (*dictionary[dindex].func)(name, value);
	    if (res < 0) Log(LOG_WARNING, "WARN: Not valid value at line: %d. Ignored.\n", index+1);
	    else if (!res) Log(LOG_WARNING, "WARN: Unknown symbol '%s'. Line %d ignored.\n", name, index+1);
	  }
	  else Log(LOG_WARNING, "WARN: Unable to handle key: %s. Ignored.\n", key);
	  key_found = TRUE;
	  break;
        }
	else key_found = FALSE;
      }

      if (!key_found) Log(LOG_WARNING, "WARN: Unknown key: %s. Ignored.\n", key);
    }

    index++;
  }
}

/* parse_configuration_file() reads configuration file
   and stores its content in an array; then creates
   plugin structures and parses supported config keys */
int parse_configuration_file(char *filename)
{
  char localbuf[10240];
  FILE *file;
  int num = 0;

  /* a NULL filename tell us we have not to parse a configuration
     file because in commandline mode. So, we'll jump directly to
     2nd stage */
  if (filename) { 
    rows = 0;

    /* 1st stage: reading from file and storing it in an array */
    if ((file = fopen(filename,"r")) == NULL) {
      Log(LOG_ERR, "ERROR: file %s not found\n", filename);
      return ERR;
    }
    else {
      while (!feof(file)) {
        if (rows == SRVBUFLEN) {
	  Log(LOG_ERR, "ERROR: maximum number of %d lines reached.\n", SRVBUFLEN);
	  break;
        }
	memset(localbuf, 0, sizeof(localbuf));
        if (fgets(localbuf, sizeof(localbuf), file) == NULL) {
	  if (debug) debug_configuration_file(rows); 
	  break;	
        }
        else {
	  localbuf[sizeof(localbuf)-1] = '\0';
          cfg[rows] = malloc(strlen(localbuf)+2);
          strcpy(cfg[rows], localbuf);
          cfg[rows][strlen(localbuf)+1] = '\0';
          rows++;
        } 
      }
    }
    fclose(file);
  }

  /* 2nd stage: sanitize lines */
  sanitize_cfg(rows);

  /* 3rd stage: plugin structures creation; we discard
     plugin names if 'pmacctd' has been invoked commandline;
     if any plugin has been activated we default to a single
     'imt' plugin */ 
  create_plugin("default", "core");
  if (filename) num = parse_plugin_names(rows, FALSE);
  else num = parse_plugin_names(rows, TRUE);
  if (!num) {
    Log(LOG_WARNING, "WARN: No plugin has been activated; defaulting to in-memory table.\n"); 
    num = create_plugin("default", "memory");
  }

  if (debug) {
    struct plugins_list_entry *list = plugins_list;
    
    while (list) {
      Log(LOG_DEBUG, "DEBUG: plugin name/type: '%s'/'%s'\n", list->name, list->type.string);
      list = list->next;
    }
  }

  /* 4th stage: setting some default value */
  set_default_values();
  
  /* 5th stage: parsing keys and building configurations */ 
  evaluate_configuration(rows);

  return SUCCESS;
}

void sanitize_cfg(int rows)
{
  int rindex = 0, len;
  char localbuf[10240];

  while (rindex < rows) {
    memset(localbuf, 0, 10240);

    /* checking the whole line: if it's a comment starting with
       '!', it will be removed */
    if (iscomment(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* checking the whole line: if it's void, it will be removed */
    if (isblankline(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* 
       a pair of syntax checks on the whole line:
       - does the line contain at least a ':' verb ?
       - are the square brackets weighted both in key and value ?
    */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0;

      if (!strchr(cfg[rindex], ':')) {
	Log(LOG_ERR, "ERROR: Syntax error: missing ':' at line %d. Exiting.\n", rindex+1); 
	exit(1);
      }
      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
        else if (cfg[rindex][cindex] == ']') symbol--;
	
	if ((cfg[rindex][cindex] == ':') || (cfg[rindex][cindex] == '\0')) {
	  if (symbol) {
            Log(LOG_ERR, "ERROR: Syntax error: not weighted brackets at line %d. Exiting.\n", rindex+1);
	    exit(1);
	  }
	}

	if (symbol < 0) {
	  Log(LOG_ERR, "ERROR: Syntax error: not weighted brackets at line %d. Exiting.\n", rindex+1);
	  exit(1);
	}

	if (symbol > 1) {
	  Log(LOG_ERR, "ERROR: Syntax error: nested symbols not allowed at line %d. Exiting.\n", rindex+1);
	  exit(1);
	}
	
	cindex++;
      }
    }

    /* checking the whole line: erasing unwanted spaces from key;
       trimming start/end spaces from value; symbols will be leaved
       untouched */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, value = FALSE, cindex = 0, lbindex = 0;
      char *valueptr;

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
        else if (cfg[rindex][cindex] == ']') symbol--;
	else if (cfg[rindex][cindex] == ':') {
	  value++;
	  valueptr = &localbuf[lbindex+1];
	}
        if ((!symbol) && (!value)) {
	  if (!isspace(cfg[rindex][cindex])) {
	    localbuf[lbindex] = cfg[rindex][cindex]; 
	    lbindex++;
	  }
        }
        else {
	  localbuf[lbindex] = cfg[rindex][cindex];
	  lbindex++;
        }
        cindex++;
      }
      localbuf[lbindex] = '\0';
      trim_spaces(valueptr);
      strcpy(cfg[rindex], localbuf);
    }

    /* checking key field: each symbol must refer to a key */
    len = strlen(cfg[rindex]);
    if (len) { 
      int symbol = FALSE, key = FALSE, cindex = 0;

      while (cindex < rows) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') {
	  symbol--;
	  key--;
	}

	if (cfg[rindex][cindex] == ':') break;

	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex])) key = TRUE;
	}
	else {
	  if (!key) {
            Log(LOG_ERR, "ERROR: Syntax error: symbol not referring to any key at line %d. Exiting.\n", rindex+1);
	    exit(1);
	  }
	}
        cindex++;
      }
    }


    /* checking key field: does a key still exist ? */
    len = strlen(cfg[rindex]);
    if (len) {
      if (cfg[rindex][0] == ':') {
	Log(LOG_ERR, "ERROR: Syntax error: missing key at line %d. Exiting.\n", rindex+1);
	exit(1);
      }
    }

    /* checking key field: converting key to lower chars */ 
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0;

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') symbol--;

	if (cfg[rindex][cindex] == ':') break;
	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex]))
	    cfg[rindex][cindex] = tolower(cfg[rindex][cindex]);
	}
	cindex++;
      }
    }

    rindex++;
  }
}

/* parse_plugin_names() leaves cfg array untouched: parses the key 'plugins'
   if it exists and creates the plugins linked list */ 
int parse_plugin_names(int rows, int ignore_names)
{
  int index = 0, num = 0, found = 0;
  char *start, *end, *start_name, *end_name;
  char key[SRVBUFLEN], value[10240], token[SRVBUFLEN], name[SRVBUFLEN];

  /* searching for 'plugins' key */
  while (index < rows) {
    memset(key, 0, SRVBUFLEN);
    start = NULL; end = NULL;

    start = cfg[index];
    end = strchr(cfg[index], ':');
    if (end > start) {
      strlcpy(key, cfg[index], (end-start)+1); 
      if (!strncmp(key, "plugins", sizeof("plugins"))) {
	start = end+1;
	strcpy(value, start); 
	found = TRUE;
	break;
      }
    }
    index++;
  }

  if (!found) return 0;

  /* parsing declared plugins */
  start = value;
  while (*end != '\0') {
    memset(token, 0, SRVBUFLEN);
    if (!(end = strchr(start, ','))) end = strchr(start, '\0');
    if (end > start) {
      strlcpy(token, start, (end-start)+1);
      if ((start_name = strchr(token, '[')) && (end_name = strchr(token, ']'))) {
        if (end_name > (start_name+1)) {
          strlcpy(name, (start_name+1), (end_name-start_name));
	  trim_spaces(name);
	  *start_name = '\0';
	}
      }
      else strcpy(name, "default");
	
      /* Having already plugins name and type, we'll filter out reserved symbols */
      trim_spaces(token);
      if (!strcmp(token, "core")) {
        Log(LOG_ERR, "ERROR: plugins of type 'core' are not allowed. Exiting.\n");
        exit(1);
      }
      if (!ignore_names) {
        if (create_plugin(name, token)) num++;
      }
      else {
        if (create_plugin("default", token)) num++;
      }
    }
    start = end+1;
  }

  /* having already processed it, we erase 'plugins' line */
  memset(cfg[index], 0, strlen(cfg[index]));

  return num;
}

/* rough and dirty function to assign default values to
   configuration file of each plugin */
void set_default_values()
{
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    list->cfg.promisc = TRUE;

    list = list->next;
  }
}

void debug_configuration_file(int rows)
{
  int index = 0;

  while (index < rows) {
    Log(LOG_DEBUG, "DEBUG: config: %s", cfg[index]);
    index++;
  }
}

int create_plugin(char *name, char *type)
{
  struct plugins_list_entry *plugin, *ptr;
  struct plugin_type_entry *ptype = NULL;
  int index = 0, id = 0;
 
  /* searching for a valid known plugin type */
  while(strcmp(plugin_types_list[index].string, "")) {
    if (!strcmp(type, plugin_types_list[index].string)) ptype = &plugin_types_list[index];
    index++;
  }

  if (!ptype) {
    Log(LOG_ERR, "ERROR: Unknown plugin type: %s. Ignoring.\n", type);
    return FALSE;
  }

  /* checks */
  if (plugins_list) {
    id = 0;
    ptr = plugins_list;
    while(ptr) {
      /* plugin id */
      if (ptr->id > id) id = ptr->id;

      /* dupes */
      if (!strcmp(name, ptr->name)) {
        if (!strcmp(type, ptr->type.string)) {
          Log(LOG_WARNING, "WARN: another plugin with the same name '%s' already exists. Preserving first.\n", name);
          return FALSE;
        }
      }
      ptr = ptr->next;
    }
    id++;
  }

  /* creating a new plugin structure */
  plugin = (struct plugins_list_entry *) malloc(sizeof(struct plugins_list_entry));
  if (!plugin) {
    Log(LOG_ERR, "ERROR: Unable to allocate memory config_plugin structure\n");
    exit(1);
  }

  memset(plugin, 0, sizeof(struct plugins_list_entry));
  
  strcpy(plugin->name, name);
  plugin->id = id;
  memcpy(&plugin->type, ptype, sizeof(struct plugin_type_entry));
  plugin->next = NULL;

  /* inserting our object in plugin's linked list */
  if (plugins_list) {
    ptr = plugins_list;
    while(ptr->next) ptr = ptr->next; 
    ptr->next = plugin;
  }
  else plugins_list = plugin;

  return TRUE;
}

int delete_plugin_by_id(int id)
{
  struct plugins_list_entry *list = plugins_list;
  struct plugins_list_entry *aux = plugins_list;
  int highest_id = 0;

  if (id == 0) return ERR;

  while (list) {
    if (list->id == id) {
      aux->next = list->next;
      free(list);
      list = aux;
    }
    else {
      if (list->id > highest_id) highest_id = list->id; 
    }
    aux = list;
    list = list->next; 
  } 

  return highest_id;
}

struct plugins_list_entry *search_plugin_by_pipe(int pipe)
{
  struct plugins_list_entry *list = plugins_list;

  if (pipe < 0) return NULL;

  while (list) {
    if (list->pipe[1] == pipe) return list; 
    else list = list->next; 
  }

  return NULL;
}

struct plugins_list_entry *search_plugin_by_pid(pid_t pid)
{
  struct plugins_list_entry *list = plugins_list;

  if (pid <= 0) return NULL;

  while (list) {
    if (list->pid == pid) return list;
    else list = list->next;
  }

  return NULL;
}
