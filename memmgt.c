/*
 * Copyright (c) 2008-2009 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <memory.h>
#include <netinet/in.h>

#include "memmgt.h"

struct unused_type {
  struct mem_buffer a;
  void *next;
  char b;
};

typedef struct mem_buffer_storage mem_buffer_storage_t;

struct mem_buffer_storage {
  struct mem_buffer buffer;
  mem_buffer_storage_t *next;
  char initial_storage[64 - offsetof(struct unused_type,b)];
};


static struct mem_buffer_storage *head;

int adjust_mem_buffer_int(struct mem_buffer_storage *buffer, size_t size) {
  void *new;
  size_t new_size = 64 * ((size + 63) / 64);
  
  if (size < buffer->buffer.allocated)
    return 0;
  if (buffer->buffer.value == buffer->initial_storage) {
    new = malloc(new_size);
    if (new && 
	buffer->buffer.length && 
	buffer->buffer.length < buffer->buffer.allocated)
      memcpy(new, buffer->initial_storage, buffer->buffer.length);
  } else {
    new = realloc(buffer->buffer.value, new_size);
  }
  if (new == NULL) 
    return 1;
  buffer->buffer.value = new;
  buffer->buffer.allocated = new_size;
  return 0;
}

struct mem_buffer *buf_alloc(size_t size) {
  struct mem_buffer_storage *cur, *prev;
  int i;

  if (size == 0)
    return (struct mem_buffer *)calloc(1, sizeof(struct mem_buffer));

  for (i=0;i <= 1; i++) {
    for (cur=head,prev=NULL;cur;prev=cur,cur=cur->next) {
      if (cur->buffer.allocated >= size)
	break;
      if (i == 1)
	break;
    }
    if (cur)
      break;
  }

  if (cur && cur->buffer.allocated < size && !adjust_mem_buffer_int(cur, size))
    cur=NULL;
  if (cur) {
    if (prev)
      prev->next = cur->next;
    else
      head = cur->next;
    cur->next = NULL;
  cur->buffer.cursor = NULL;
  return &cur->buffer;
  }

  cur=calloc(1, sizeof(struct mem_buffer_storage));
  if (!cur)
    return NULL;
  cur->buffer.value = cur->initial_storage;
  cur->buffer.allocated = sizeof(cur->initial_storage);
  cur->buffer.cursor = NULL;
  if (adjust_mem_buffer_int(cur, size)) {
    free(cur);
    return NULL;
  }
  return (&cur->buffer);
}

void buf_free(struct mem_buffer *buffer) {
  struct mem_buffer_storage *internal;

  buffer->length = 0;
  if (buffer->allocated == 0) {
    free(buffer);
    return;
  }
  internal = (struct mem_buffer_storage *)buffer;
  internal->next = head;
  head = internal;
}

  
int buf_grow(struct mem_buffer *buffer, size_t size) {
  struct mem_buffer_storage *internal;
  int ret, offset;
  
  if (buffer->cursor) {
    unsigned char *p, *q;
    p=buffer->value;
    q=buffer->cursor;
    offset = q - p;
  } else
    offset = -1;
  
  internal = (struct mem_buffer_storage *)buffer;
  ret = adjust_mem_buffer_int(internal, size);
  if (ret == 0 && offset >= 0) {
    unsigned char *p;
    p = buffer->value;
    buffer->cursor = p + offset;
  }
  return ret;
}

int buf_setlength(struct mem_buffer *buffer, const size_t newlength) {
  if (newlength > buffer->allocated) {
    if (buf_grow(buffer, newlength))
      return 1;
  }
  buffer->length = newlength;
  reset_cursor(buffer);
  return 0;
}

static int buf_checkdata(struct mem_buffer *buffer, const size_t need) {
  unsigned char *p, *q;
  size_t avail;

  p = buffer->value;
  q = buffer->cursor;
  /* check for valid cursor position */
  if (!q || q < p || q > p + buffer->length)
    return 1;
  if (need == 0)
    return 0;
  avail = buffer->length - (q - p);
  return (avail < need);
}

int buf_putdata(struct mem_buffer *buffer, 
		const void *data, const size_t datalen) {
  if (buf_checkdata(buffer, datalen))
    return 1;
  memcpy(buffer->cursor, data, datalen);
  buffer->cursor = (char *)buffer->cursor + datalen;
  return 0;
}

int buf_putint(struct mem_buffer *buffer, const unsigned int data) {
     unsigned int sdata = htonl(data);
     return buf_putdata(buffer, &sdata, 4);
}

int buf_putstring(struct mem_buffer *buffer, const char * data) {
  size_t slen = strlen(data);
  return buf_putint(buffer, slen) || buf_putdata(buffer, data, slen);
}

int buf_appenddata(struct mem_buffer *buffer, 
                   const void *data, const size_t datalen) {
  size_t newlength = buffer->length + datalen;

  /* make sure cursor is valid */
  if (buffer->cursor == NULL)
    buffer->cursor = buffer->value;
  else if (buf_checkdata(buffer, 0))
    return 1;
  
  if (newlength > buffer->allocated) {
    if (buf_grow(buffer, newlength))
      return 1;
  }
  buffer->length = newlength;
  return buf_putdata(buffer, data, datalen); /* shouldn't fail. assert? */
}

int buf_appendint(struct mem_buffer *buffer, const unsigned int data) {
     unsigned int sdata = htonl(data);
     return buf_appenddata(buffer, &sdata, 4);
}

int buf_appendstring(struct mem_buffer *buffer, const char * data) {
  size_t slen = strlen(data);
  return buf_appendint(buffer, slen) || buf_appenddata(buffer, data, slen);
}

int buf_getdata(struct mem_buffer *buffer, 
		void *data, const size_t datalen) {
  if (buf_checkdata(buffer, datalen))
    return 1;
  memcpy(data, buffer->cursor, datalen);
  buffer->cursor = (char *)buffer->cursor + datalen;
  return 0;
}

int buf_getint(struct mem_buffer *buffer, unsigned int *data) {
     unsigned int sdata;
     
     if (buf_getdata(buffer, &sdata, 4))
          return 1;
     *data = ntohl(sdata);
     return 0;
}

/* *datap may be valid and allocated even if this function fails! */
int buf_getstring(struct mem_buffer *buffer, char **datap, 
                  void *(*alloc)(size_t)) 
{
  unsigned int slen;
  char *ret;
  *datap=NULL;
  if (buf_getint(buffer, &slen))
    return 1;
  if (slen == UINT_MAX) /* some lower limit could be chosen. Just don't want to overflow the +1 */
    return 1;
  ret = alloc(slen + 1);
  if (!ret)
    return 1;
  *datap=ret;
  ret[slen]=0;
  return buf_getdata(buffer, ret, slen);
}

