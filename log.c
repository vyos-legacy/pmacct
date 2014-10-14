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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"

/* functions */
void Log(short int level, char *msg, ...)
{
  va_list ap;
  char syslog_string[LOGSTRLEN];

  if (!config.syslog) {
    va_start(ap, msg);
    vprintf(msg, ap);
    va_end(ap);
  }
  else {
    va_start(ap, msg);
    vsnprintf(syslog_string, LOGSTRLEN, msg, ap);
    va_end(ap);
    sbrk(LOGSTRLEN);
    syslog(level, syslog_string);
    sbrk(-LOGSTRLEN);
  }
}

int parse_log_facility(const char *facility)
{
  int i;
  
  for (i = 0; facility_map[i].num != -1; i++) {
    if (!strcmp(facility, facility_map[i].string))
      return facility_map[i].num; 
  }

  return ERR;
}
