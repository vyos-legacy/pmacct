/* includes */
#include "pmacct.h"

/* functions */
void setnonblocking(int sock)
{
  int opts;

  opts = fcntl(sock,F_GETFL);
  opts = (opts | O_NONBLOCK);
  fcntl(sock,F_SETFL,opts);
}

void setblocking(int sock)
{
  int opts;

  opts = fcntl(sock, F_GETFL);
  opts & O_NONBLOCK ? opts ^= O_NONBLOCK : opts;
  fcntl(sock, F_SETFL, opts);
}

int daemonize()
{
  int fdd;
  pid_t pid;

  pid = fork();

  switch (pid) {
  case -1:
    return -1;
  case 0:
    break;
  default:
    exit(0);
  }

  if (setsid() == -1) return -1;

  fdd = open("/dev/null", O_RDWR, 0);
  if (fdd != -1) {
    dup2(fdd, 0);
    dup2(fdd, 1);
    dup2(fdd, 2); 
    if (fdd > 2) close(fdd);
  }

  return 0;
}

char *extract_token(char **string, int delim)
{
  char *token, *delim_ptr;

  if ((delim_ptr = strchr(*string, delim))) {
    *delim_ptr = '\0';
    token = *string;
    *string = delim_ptr+1;
  }
  else {
    token = *string;
    *string += strlen(*string);
  }

  return token;
}

char *extract_plugin_name(char **string)
{
  char *name, *delim_ptr;
  char name_start = '[';
  char name_end = ']';

  if ((delim_ptr = strchr(*string, name_start))) {
    *delim_ptr = '\0';
    name = delim_ptr+1; 
    if ((delim_ptr = strchr(name, name_end))) *delim_ptr = '\0';
    else {
      printf("ERROR: Not weighted parhentesis: '[%s'\n", name); 
      exit(1);
    }
  }
  else return NULL;

  return name;
}


/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

char *copy_argv(register char **argv)
{
  register char **p;
  register unsigned int len = 0;
  char *buf;
  char *src, *dst;

  p = argv;
  if (*p == 0)
    return NULL;

  while (*p)
    len += strlen(*p++) + 1;

   buf = (char *)malloc(len);
   if (buf == NULL) {
     Log(LOG_ERR, "ERROR: copy_argv: malloc()\n");
     return NULL;
   }

   p = argv;
   dst = buf;
   while ((src = *p++) != NULL) {
     while ((*dst++ = *src++) != '\0');
     dst[-1] = ' ';
   }

   dst[-1] = '\0';
   return buf;
}

void trim_spaces(char *buf)
{
  char *ptr;
  int i, len;

  ptr = buf;
  len = strlen(buf);
   
  /* trimming spaces at beginning of the string */
  for (i = 0; i <= len; i++) {
    if (!isspace(ptr[i])) {
      strcpy(buf, &ptr[i]); 
      break;
    } 
  }

  /* trimming spaces at the end of the string */
  for (i = strlen(buf)-1; i >= 0; i--) { 
    if (isspace(ptr[i]))
      ptr[i] = '\0';
    else break;
  }
}

void trim_all_spaces(char *buf)
{
  char *ptr;
  int i, len;

  ptr = buf;
  len = strlen(buf);

  /* trimming all spaces */
  for (i = 0; i <= len; i++) {
    if (isspace(ptr[i])) {
      strcpy(&buf[i], &ptr[i+1]);
    }
  }
}

int isblankline(char *line)
{
  int len, j, n_spaces = 0;
 
  if (!line) return FALSE;

  len = strlen(line); 
  for (j = 0; j < len; j++) 
    if (isspace(line[j])) n_spaces++;

  if (n_spaces == len) return TRUE;
  else return FALSE;
}

int iscomment(char *line)
{
  int len, j, first_char = TRUE;

  if (!line) return FALSE;

  len = strlen(line);
  for (j = 0; j <= len; j++) {
    if (!isspace(line[j])) first_char--;
    if (!first_char) {
      if (line[j] == '!') return TRUE; 
      else return FALSE;
    }
  }

  return FALSE;
}

void debug_packet(struct pkt_data *data)
{
  if (data != NULL) {
    Log(LOG_DEBUG, "This packet len: %d\n", ntohs(data->pkt_len));
    if (config.what_to_count & COUNT_SRC_MAC)
      Log(LOG_DEBUG, "Src MAC: %s\n", (char *)ether_ntoa(data->primitives.eth_shost));

    if (config.what_to_count & COUNT_DST_MAC)
      Log(LOG_DEBUG, "Dst MAC: %s\n", (char *)ether_ntoa(data->primitives.eth_dhost));

    if (config.what_to_count & COUNT_SRC_HOST)
      Log(LOG_DEBUG, "Src host: %s\n", inet_ntoa(data->primitives.src_ip));

    if (config.what_to_count & COUNT_DST_HOST)
      Log(LOG_DEBUG, "Dst host: %s\n", inet_ntoa(data->primitives.dst_ip));

    if (config.what_to_count & COUNT_SRC_PORT)
      Log(LOG_DEBUG, "Src port: %d\n", ntohs(data->primitives.src_port));

    if (config.what_to_count & COUNT_DST_PORT)
      Log(LOG_DEBUG, "Dst port: %d\n", ntohs(data->primitives.dst_port));

    if (config.what_to_count & COUNT_IP_PROTO)
      Log(LOG_DEBUG, "Proto: %d\n", data->primitives.proto);
  }
}

time_t roundoff_time(time_t t)
{
  char *value = config.sql_history_roundoff;
  struct tm *rounded;
  int len, j;

  rounded = localtime(&t);
  rounded->tm_sec = 0; /* default round off */

  if (value) {
    len = strlen(value);
    for (j = 0; j < len; j++) {
      if (value[j] == 'm') rounded->tm_min = 0;
      else if (value[j] == 'h') rounded->tm_hour = 0;
      else if (value[j] == 'd') rounded->tm_mday = 1;
      else Log(LOG_WARNING, "WARN: ignoring unknown round off value: %c\n", value[j]); 
    }
  }

  t = mktime(rounded);
  return t;
}

void write_pid_file(char *filename)
{
  FILE *file;
  char pid[10];

  if ((file = fopen(filename,"w")) == NULL) {
    Log(LOG_ERR, "ERROR: file %s not found\n", filename);
    return;
  }
  
  sprintf(pid, "%d\n", getpid()); 
  fwrite(pid, strlen(pid), 1, file);
  fclose(file);
}

int sanitize_buf_net(char *buf, int rows)
{
  if (!sanitize_buf(buf)) {
    if (!strchr(buf, '/')) {
      Log(LOG_ERR, "ERROR: Missing '/' separator at line %d. Ignoring.\n", rows);
      return TRUE;
    }
  }
  else return TRUE;

  return FALSE;
}

int sanitize_buf(char *buf)
{
  int x = 0, valid_char = 0;

  trim_all_spaces(buf);
  while (x < strlen(buf)) {
    if (!isspace(buf[x])) valid_char++;
    x++;
  }
  if (!valid_char) return TRUE;
  if (buf[0] == '!') return TRUE;

  return FALSE;
}

int check_not_valid_char(char *buf, int c)
{
  if (!buf) return FALSE;
  
  if (strchr(buf, c)) {
    Log(LOG_ERR, "ERROR: Invalid symbol '%c' detected. ", c);
    return TRUE; 
  }
  else return FALSE;
}

void mark_columns(char *buf)
{
  int len, x, word = FALSE;

  if (!buf) return;

  len = strlen(buf);
  for (x = 0; x < len; x++) {
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    if (isspace(buf[x]) && word) {
      buf[x] = ';';
      word = FALSE;
    }
  }

  /* removing trailing ';' if any */
  x = strlen(buf);
  word = FALSE;

  while (x > 0) {
    if (buf[x] == ';' && !word) buf[x] = '\0';
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    x--;
  }
}

int Setsocksize(int s, int level, int optname, void *optval, int optlen)
{
  int ret, len, saved, value;

  memcpy(&value, optval, sizeof(int));
  
  getsockopt(s, level, optname, &saved, &len);
  if (value > saved) {
    for (; value; value >>= 1) {
      ret = setsockopt(s, level, optname, &value, optlen); 
      if (ret >= 0) break;
    }
    if (!value) setsockopt(s, level, optname, &saved, len); 
  }

  return ret;
}

void *map_shared(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
#if defined USE_DEVZERO
  void *mem;
  int devzero;

  devzero = open ("/dev/zero", O_RDWR);
  if (devzero < 0) return MAP_FAILED;
  mem = mmap(addr, len, prot, flags, devzero, off);
  close(devzero);

  return mem;
#else /* MAP_ANON or MAP_ANONYMOUS */
  return (void *)mmap(addr, len, prot, flags, fd, off);
#endif
}
