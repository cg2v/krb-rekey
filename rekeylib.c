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
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <krb5.h>
#ifdef HEADER_GSSAPI_GSSAPI
#include <gssapi/gssapi.h>
#else
#include <gssapi.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "memmgt.h"
#include "rekey-locl.h"

void fatal(const char *msg, ...) {
     va_list ap;
     va_start(ap, msg);
     vprtmsg( msg, ap);
     va_end(ap);
     exit(1);
}


void prtmsg(const char *msg, ...) {
     va_list ap;
     va_start(ap, msg);
     vprtmsg( msg, ap);
     va_end(ap);
}
static int do_ssl_error(const char *str, size_t len, void *u) {
  prtmsg("%.*s", len, str);
  return 0;
}
void ssl_fatal(SSL *ssl, int code) {
  if (ERR_peek_error()) {
    ERR_print_errors_cb(do_ssl_error, NULL);
  } else if (ssl && code < 1){
    int code2 = SSL_get_error(ssl, code);
    if (code2 == SSL_ERROR_SYSCALL) {
      if (errno == 0)
        prtmsg("Connection closed");
      else
        prtmsg("SSL failed due to i/o error: %s", strerror(errno));
    } else {
      prtmsg("SSL failed for an unknown reason (code = %d, error = %d)",
             code, code2);
    }
  } else {
    prtmsg("SSL failed, but no information is available (code = %d)", code);
  }
  exit(1);
}

void do_send(SSL *ssl, int opcode, mb_t data) {
  mb_t actual;
  struct mem_buffer empty;
  int rc;
  unsigned char opc;

  if (!data) {
    empty.length=0;
    data = &empty;
  }
  actual = buf_alloc(5 + data->length);
  if (!actual) 
    fatal("memory allocation failed: %s", strerror(errno));
  buf_setlength(actual, 5 + data->length);
  opc = opcode & 0xFF;
  if (buf_putdata(actual, &opc, 1))
    fatal("Impossible error. buffer too small!");
  if (buf_putint(actual, data->length))
    fatal("Impossible error. buffer too small!");
  if (data->length)
    buf_putdata(actual, data->value, data->length);
  rc = SSL_write(ssl, actual->value, actual->length);
  if (rc < 0)
    ssl_fatal(ssl, rc);
  else if (rc == 0)
    fatal("Connection closed");
  else if (rc !=  5 + data->length)
    fatal("Short write");
  buf_free(actual);
}

int do_recv(SSL *ssl, mb_t data) {
  unsigned char opc;
  int rc, opcode;
  unsigned int rlen;
  
  if (buf_setlength(data, 5))
    fatal("memory allocation failed: %s", strerror(errno));
  rc = SSL_read(ssl, data->value, 5);
  if (rc < 0)
    ssl_fatal(ssl, rc);
  else if (rc == 0) {
    return -1;
    /*fatal("Connection closed");*/
  } else if (rc != 5)
    fatal("Short read");
  if (buf_getdata(data, &opc, 1))
    fatal("Impossible error. buffer too small!");
  opcode = opc;
  if (buf_getint(data, &rlen))
    fatal("Impossible error. buffer too small!");
  if (buf_setlength(data, rlen))
      fatal("memory allocation failed: %s", strerror(errno));
  if (rlen > 0) {
      rc = SSL_read(ssl, data->value, rlen);
      if (rc < 0)
        ssl_fatal(ssl, rc);
      else if (rc == 0)
        fatal("Connection closed");
      else if (rc != rlen)
        fatal("Short read");
  }
  return opcode == -1 ? -2 : opcode;
}

void do_gss_error(gss_OID mech, OM_uint32 errmaj, OM_uint32 errmin,
                  void (*cb)(void *, gss_buffer_t), void *rock) {
     OM_uint32 message_context;
     OM_uint32 maj_status;
     OM_uint32 min_status;
     gss_buffer_desc status_string;
     
     message_context = 0;
     
     do {
          maj_status = gss_display_status (
               &min_status,
               errmaj,
               GSS_C_GSS_CODE,
               mech,
               &message_context,
               &status_string);
               
	  if (GSS_ERROR(maj_status)) {
	    prtmsg("gss_display_status (GSS_CODE for %d) failed: %d:%d",
		    errmaj, maj_status, min_status);
	    break;
	  }
          cb(rock, &status_string);
	  gss_release_buffer(&min_status, &status_string);
          
     } while (message_context != 0);
     
     if (errmin) {
          message_context = 0;
          
          do {
               maj_status = gss_display_status (
                    &min_status,
                    errmaj,
                    GSS_C_MECH_CODE,
                    mech,
                    &message_context,
                    &status_string);
	       
	       if (GSS_ERROR(maj_status)) {
		 prtmsg("gss_display_status (MECH_CODE for %d) failed: %d:%d",
			 errmin, maj_status, min_status);
		 break;
	       }
               cb(rock, &status_string);
               gss_release_buffer(&min_status, &status_string);
               
          } while (message_context != 0);
     }
}

void prt_gss_error_cb(void *rock, gss_buffer_t status_string) 
{
  prtmsg("%.*s",
         (int)status_string->length,
         (char *)status_string->value);
}

void prt_gss_error(gss_OID mech, OM_uint32 errmaj, OM_uint32 errmin) {
  do_gss_error(mech, errmaj, errmin, prt_gss_error_cb, NULL);
}

static size_t my_strnlen(char *s, size_t n) 
{
  size_t ret=0;
  while (*s && n > 0) {
    s++; 
    n--;
    ret++;
  }
  return ret;
}

void prt_err_reply(mb_t resp) {
  unsigned int len, code;
  char *msg, *q;
  reset_cursor(resp);
  if (buf_getint(resp, &code)) {
    prtmsg("Malformed error reply (too short to contain code)");
    return;
  }
  if (buf_getstring(resp, &msg, malloc)) {
    prtmsg("Remote error: %d", code);
    prtmsg("Malformed error reply (too short to contain message length)");
    return;
  }
  len = strlen(msg);
  q = msg;
  while (q < &msg[len]) {
    prtmsg("Remote error: %s (%d)", q, code);
    q += my_strnlen(q, len - (q - msg));
    q++;
  }
  free(msg);
}
