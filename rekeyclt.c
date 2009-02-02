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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
/* gnulib */
#include "getaddrinfo.h"
#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif
#ifdef HEADER_GSSAPI_GSSAPI
#include <gssapi/gssapi.h>
#else
#include <gssapi.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "memmgt.h"
#include "rekey-locl.h"
#include "protocol.h"

static SSL_CTX *sslctx;

void vprtmsg(const char *msg, va_list ap) {
     vfprintf(stderr, msg, ap);
     fputs("\n", stderr);
}

static void ssl_startup(void) {
  int rc;
     SSL_library_init();
     ERR_load_crypto_strings();
     ERR_load_SSL_strings();
     
     sslctx=SSL_CTX_new(TLSv1_client_method());
     if (!sslctx)
       ssl_fatal(NULL, 0);
     rc=SSL_CTX_set_cipher_list(sslctx, "aNULL:-EXPORT:-LOW:-MD5");
     if (rc == 0)
       ssl_fatal(NULL, 0);
}

static SSL *do_connect(char *hostname) {
     SSL *ret;
     struct addrinfo ahints, *conn, *p;
     int s;
     int rc;
     
     memset(&ahints, 0, sizeof(ahints));
     ahints.ai_flags = AI_ADDRCONFIG|AI_NUMERICSERV;
     ahints.ai_family = PF_UNSPEC;
     ahints.ai_socktype = SOCK_STREAM;
     
     if (strlen(hostname) < 16 && hostname[0] >= '0' && hostname[0] <= '9')
          ahints.ai_flags |= AI_NUMERICHOST;
     
     rc = getaddrinfo(hostname, "4446", &ahints, &conn);
     if (rc)
          fatal("hostname lookup failed: %s", gai_strerror(rc));
     
     for (p=conn; p; p=p->ai_next) {
          
          s=socket(p->ai_family, p->ai_socktype, p->ai_protocol);
          if (s < 0)
               continue;
          rc = connect(s, p->ai_addr, p->ai_addrlen);
          if (rc == 0)
               break;
          close(s);
     }
     if (p == NULL)
          fatal("Cannot connect to %s: %s", hostname, strerror(errno));
     freeaddrinfo(conn);
     
     ret=SSL_new(sslctx);
     if (!ret)
       ssl_fatal(NULL, 0);
          
     rc=SSL_set_fd(ret, s);
     if (rc == 0)
       ssl_fatal(ret, rc);
     
     rc=SSL_connect(ret);
     if (rc != 1)
       ssl_fatal(ret, rc); /* probably wrong */
     
     return ret;
}

static int sendrcv(SSL *ssl, int opcode, mb_t data) {
  int ret;
  do_send(ssl, opcode, data);
  ret=do_recv(ssl, data);
  if (ret == -1) {
     SSL_shutdown(ssl);
     SSL_free(ssl);
     fatal("Connection closed");
  }
}

static void do_auth(SSL *ssl, char *hostname) {
 unsigned char *p;
     
 OM_uint32 maj, min, rflag;
 gss_name_t n=NULL;
 gss_ctx_id_t gctx=GSS_C_NO_CONTEXT;
 gss_buffer_desc inname, in, out;
 gss_buffer_t inp=GSS_C_NO_BUFFER;
 gss_OID mech;
 int gss_more_init=1,gss_more_accept=1, flen;
 int resp=0;
 mb_t mic;
 gss_qop_t qop;
     
 char namebuf[256];
     
 memset(namebuf, 0, 256);
 snprintf(namebuf, 255, "host@%s", hostname);
     
 inname.value=namebuf;
 inname.length=strlen(namebuf);
     
 maj = gss_import_name(&min, &inname, GSS_C_NT_HOSTBASED_SERVICE, &n);
     
 if (GSS_ERROR(maj)) {
   prt_gss_error(GSS_C_NO_OID, maj, min);
   SSL_shutdown(ssl);
   fatal("Cannot authenticate");
 }
     
 memset(&out, 0, sizeof(out));
 do {
   maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &gctx,
                              n, GSS_C_NO_OID, 
                              GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG,
                              0, GSS_C_NO_CHANNEL_BINDINGS,
                              inp, &mech, &out, &rflag, NULL);
   if (inp) {
     free(inp->value);
     inp->value=0;
   }
   if (GSS_ERROR(maj)) {
     prt_gss_error(mech, maj, min);
     gss_more_init=0;
   } else {
     if (!(maj & GSS_S_CONTINUE_NEEDED)) {
       gss_more_init=0;
     } else {
       if (out.length == 0) {
         SSL_shutdown(ssl);
         fatal("Authentication failed: not sending a gss token but expects a reply");
       }
     }
   }
   if (resp == RESP_AUTHERR) {
     SSL_shutdown(ssl);
     exit(1);
   }
   
   if (out.length && gss_more_accept == 0) {
     SSL_shutdown(ssl);
     fatal("Authentication failed: would send a gss token when remote does not expect one");
   }
   
   if (out.length) {
     mb_t auth;
     OM_uint32 f;

     auth = buf_alloc(out.length + 8);
     if (auth == NULL) {
       SSL_shutdown(ssl);
       fatal("Cannot authenticate: memory allocation failed: %s",
             strerror(errno));
     }
             
     buf_setlength(auth, out.length + 8);
     reset_cursor(auth);
               
     f=0;
     if (gss_more_init) f|=AUTHFLAG_MORE;
     if (buf_putint(auth, f) || 
	 buf_putint(auth, out.length) ||
	 buf_putdata(auth,  out.value, out.length)) {
       SSL_shutdown(ssl);
       fatal("internal error: cannot pack authentication structure");
     }
               
     resp = sendrcv(ssl, GSS_ERROR(maj) ? OP_AUTHERR : OP_AUTH, auth);
     if (resp == RESP_ERR || resp == RESP_FATAL) {
       SSL_shutdown(ssl);
       prt_err_reply(auth);
       exit(1);
     }
     if (resp == RESP_OK) {
       buf_free(auth);
       if (gss_more_init) {
         SSL_shutdown(ssl);
         fatal("Cannot authenticate: server did not send authentication reply");
       }
       gss_more_accept = 0;
     } else {
       if (resp == RESP_AUTH || resp == RESP_AUTHERR) {
	 reset_cursor(auth);
         if (buf_getint(auth, &f) ||
	     buf_getint(auth, (unsigned int *)&in.length)) {
	   SSL_shutdown(ssl);
	   fatal("Cannot authenticate: server sent malformed reply");
	 }   
	 in.value=malloc(in.length);
	 if (in.value == NULL) {
	   SSL_shutdown(ssl);
	   fatal("Cannot authenticate: memory allocation failed: %s",
             strerror(errno));
	 }
	 if (buf_getdata(auth, in.value, in.length)) {
	   SSL_shutdown(ssl);
	   fatal("Cannot authenticate: server sent malformed reply");
	 }   
	 buf_free(auth);
	 if (resp == RESP_AUTH && (f & AUTHFLAG_MORE))
           gss_more_accept = 1;
         else
           gss_more_accept = 0;

         inp = &in;
       } else {
         SSL_shutdown(ssl);
         fatal("Cannot authenticate: server sent unexpected response %d", resp);
       }                    
     }       
   }
   if (GSS_ERROR(maj)) {
     SSL_shutdown(ssl);
     exit(1);
   }
 } while (gss_more_init);
 if ((~rflag) & (GSS_C_MUTUAL_FLAG|GSS_C_INTEG_FLAG)) {
   SSL_shutdown(ssl);
   fatal("GSSAPI mechanism does not provide data integrity services");
 }

 flen = SSL_get_finished(ssl, NULL, 0);
 if (flen == 0) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: ssl finished message not available");
 }    
 in.length = 2 * flen;
 in.value = malloc(in.length);
 if (in.value == NULL) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: memory allocation failed: %s",
         strerror(errno));
 }
 p=in.value;
 if (flen != SSL_get_finished(ssl, p, flen)) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_peer_finished(ssl, p, flen)) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }
     
 maj = gss_get_mic(&min, gctx, GSS_C_QOP_DEFAULT, &in, &out);
 if (GSS_ERROR(maj)) {
   prt_gss_error(mech, maj, min);
   SSL_shutdown(ssl);
   exit(1);
 }

  mic=buf_alloc(out.length);
  if (mic == NULL)
    fatal("Cannot allocate memory: %s", strerror(errno));
  buf_setlength(mic, out.length);
  buf_putdata(mic, out.value, out.length);
  resp = sendrcv(ssl, OP_AUTHCHAN, mic);
  if (resp == RESP_ERR || resp == RESP_FATAL) {
   SSL_shutdown(ssl);
   prt_err_reply(mic);
   exit(1);
 }
 if (resp != RESP_AUTHCHAN) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: server sent unexpected response %d", 
         resp);
 }
 gss_release_buffer(&min, &out);
 out.length = mic->length;
 out.value = mic->value;

 p=in.value;
 if (flen != SSL_get_peer_finished(ssl, p, flen)) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_finished(ssl, p, flen)) {
   SSL_shutdown(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 maj = gss_verify_mic(&min, gctx, &in, &out, &qop);
 buf_free(mic);
 if (maj == GSS_S_BAD_SIG) {
   SSL_shutdown(ssl);
   fatal("channel binding verification failed (signature does not match)");
 }
     
 if (GSS_ERROR(maj)) {
   prt_gss_error(mech, maj, min);
   SSL_shutdown(ssl);
   exit(1);
 }
 free(in.value);
 gss_delete_sec_context(&min, &gctx, GSS_C_NO_BUFFER);
 gss_release_name(&min, &n);
}

void do_newreq(SSL *ssl, char *princ, int flag, int nhosts, char **hosts) 
{
  mb_t buf;
  size_t curlen;
  int i, resp;
  
  if (nhosts < 1) {
    prtmsg("Host list is empty");
    return;
  }
  buf = buf_alloc(4 + strlen(princ) + 4 + 4 + nhosts * (4 + strlen(hosts[0])));
  if (!buf) {
    SSL_shutdown(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  curlen=4 + strlen(princ) + 4 + 4;
  if (buf_setlength(buf, curlen) ||
      buf_putint(buf, strlen(princ)) ||
      buf_putdata(buf, princ, strlen(princ)) ||
      buf_putint(buf, flag) ||
      buf_putint(buf, nhosts)) {
    SSL_shutdown(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  for (i=0;i<nhosts;i++) {
    int l = strlen(hosts[i]);
    if (buf_setlength(buf, curlen + 4 + l)) {
      SSL_shutdown(ssl);
      fatal("Cannot extend buffer: %s", strerror(errno));
    } 
    set_cursor(buf, curlen);
    if (buf_putint(buf, l) ||
        buf_putdata(buf, hosts[i], l)) {
      SSL_shutdown(ssl);
      fatal("Internal error: Cannot append to buffer");
    } 
    curlen = curlen + 4 + l;
  }
  resp = sendrcv(ssl, OP_NEWREQ, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    SSL_shutdown(ssl);
    exit(1);
  }
  if (resp != RESP_OK) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
  prtmsg("Request created successfully");
 out:
  buf_free(buf);
}

void do_status(SSL *ssl, char *princ) {
  mb_t buf;
  unsigned int f, i, n, l, resp;
  char *hostname=NULL, *new;
  size_t curlen;

  buf = buf_alloc(4 + strlen(princ));
  if (!buf) {
    SSL_shutdown(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  curlen=4 + strlen(princ);
  if (buf_setlength(buf, curlen) ||
      buf_putint(buf, strlen(princ)) ||
      buf_putdata(buf, princ, strlen(princ))) {
    SSL_shutdown(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_STATUS, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    SSL_shutdown(ssl);
    exit(1);
  }
  if (resp != RESP_STATUS) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
  reset_cursor(buf);
  if (buf_getint(buf, &f) ||
      buf_getint(buf, &n)) {
    prtmsg("Server sent malformed reply");
    goto out;
  }
  
  if (f != 0)
    prtmsg("Unknown flags 0x%x received", f);
    
  for (i=0; i<n; i++) {
    if (buf_getint(buf, &f) ||
      buf_getint(buf, &l)) {
      prtmsg("Server sent malformed reply");
    }
    new = realloc(hostname, l + 1);
    if (!new) {
      SSL_shutdown(ssl);
      fatal("Cannot allocate memory");
    }
    hostname=new;
    if (buf_getdata(buf, hostname, l)) {
      prtmsg("Server sent malformed reply");
      goto out;
    }   
    hostname[l]=0;
    prtmsg("Host %s has%s finished rekeying for this principal",
           hostname, (f & STATUSFLAG_COMPLETE) ? "" : " not");
  }
 out:
  free(hostname);
  buf_free(buf);
}

#ifdef HAVE_KRB5_KEYBLOCK_ENCTYPE
#define Z_keydata(keyblock)     ((keyblock)->contents)
#define Z_keylen(keyblock)      ((keyblock)->length)
#define Z_enctype(keyblock)     ((keyblock)->enctype)
#else
#define Z_keydata(keyblock)     ((keyblock)->keyvalue.data)
#define Z_keylen(keyblock)      ((keyblock)->keyvalue.length)
#define Z_enctype(keyblock)     ((keyblock)->keytype)
#endif
#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK
#define kte_keyblock(kte) (&kte.keyblock)
#else
#define kte_keyblock(kte) (&kte.key)
#endif

#ifndef HAVE_KRB5_GET_ERR_TEXT
#include <com_err.h>
#define krb5_get_err_text(c, r) error_message(r)
#endif

void do_getkeys(SSL *ssl) {
  krb5_context ctx=NULL;
  krb5_keytab kt=NULL;
  krb5_keytab_entry ent;
  krb5_keyblock key;
  krb5_error_code rc;
  mb_t buf, commitbuf;
  unsigned int l, m, n, resp, i, j, no_send=0, 
    no_send_single, skip, kvno, et;
  char *new, *principal=NULL;

  memset(&ent, 0, sizeof(ent));

  buf=buf_alloc(1);
  if (!buf) {
    SSL_shutdown(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  commitbuf=buf_alloc(1);
  if (!commitbuf) {
    SSL_shutdown(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  rc = krb5_init_context(&ctx);
  if (rc) {
    prtmsg("krb5_init_context failed (%s)", krb5_get_err_text(ctx, rc));
    goto out;
  } 
  rc = krb5_kt_resolve(ctx, "WRFILE:tmp.keytab", &kt);
  if (rc) {
    rc = krb5_kt_resolve(ctx, "FILE:tmp.keytab", &kt);
    if (rc) {
      prtmsg("krb5_kt_resolve failed (%s)", krb5_get_err_text(ctx, rc));
      goto out;
    }
  } 

  buf_setlength(buf, 0);
  resp = sendrcv(ssl, OP_GETKEYS, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    SSL_shutdown(ssl);
    exit(1);
  }
  if (resp != RESP_KEYS) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
  if (buf_getint(buf, &m)) {
    prtmsg("Server sent malformed reply");
    goto out;
  }
  for (i=0; i < m; i++) {
    if (buf_getint(buf, &l)) {
      prtmsg("Server sent malformed reply");
      goto out;
    } 
    new = realloc(principal, l+1);
    if (!new) {
      SSL_shutdown(ssl);
      fatal("Memory allocation failed: %s", strerror(errno));
    } 
    principal = new;
    if (buf_getdata(buf, principal, l) ||
	buf_getint(buf, &kvno) ||
	buf_getint(buf, &n)){
      prtmsg("Server sent malformed reply");
      goto out;
    } 
    principal[l]=0;
    skip=0;
    rc = krb5_parse_name(ctx, principal, &ent.principal);
    if (rc) {
      prtmsg("Cannot parse principal name '%s': %s", principal, krb5_get_err_text(ctx, rc));
      skip=1;
    }
    ent.vno = kvno;
    no_send_single=0;
    for (j=0; j < n; j++) {
      if (buf_getint(buf, &et) ||
	  buf_getint(buf, &l)) {
	prtmsg("Server sent malformed reply");
	goto out;
      } 
      if (skip) {
	buf->cursor+=l;
	continue;
      }
      Z_enctype(&key)= et;
      Z_keylen(&key) = l;
      Z_keydata(&key) = malloc(l);
      if (!Z_keydata(&key)) {
	SSL_shutdown(ssl);
	fatal("Memory allocation failed: %s", strerror(errno));
      } 
      if (buf_getdata(buf, Z_keydata(&key), l)) {
	free(Z_keydata(&key));
	prtmsg("Server sent malformed reply");
	goto out;
      }
      {
	krb5_keyblock *cmp;
	rc = krb5_kt_read_service_key(ctx, "FILE:tmp.keytab", ent.principal,
				      ent.vno, et, &cmp);
	if (rc == 0) {
	  if (Z_keylen(&key) != Z_keylen(cmp) ||
	      memcmp(Z_keydata(&key), Z_keydata(cmp), Z_keylen(&key))) {
	    prtmsg("This keytab has an entry for principal %s, kvno %u, enctype %u with a different key!", 
		   principal, kvno, et);
	    no_send_single=1;
	  }
	  krb5_free_keyblock(ctx, cmp);
	  free(Z_keydata(&key));
	  continue;
	}
      }
      rc = krb5_copy_keyblock_contents(ctx, &key, kte_keyblock(ent));
      free(Z_keydata(&key));
      if (rc) {
	prtmsg("krb5_copy_keyblock_contents failed: %s", krb5_get_err_text(ctx, rc));
	no_send_single=1;
	continue;
      }
      rc = krb5_kt_add_entry(ctx, kt, &ent);
      if (rc) {
	prtmsg("krb5_kt_add_entry failed: %s", krb5_get_err_text(ctx, rc));
	no_send_single=1;
      }
      krb5_free_keyblock_contents(ctx, kte_keyblock(ent));
    }
    /* maybe close & reopen keytab? */
    if (skip == 0 && no_send == 0 && no_send_single == 0) {
      if (buf_setlength(commitbuf, 8+strlen(principal))) {
	SSL_shutdown(ssl);
	fatal("Internal error: Cannot extend buffer: %s", strerror(errno));
      }
      if (buf_putint(commitbuf, strlen(principal)) ||
	  buf_putdata(commitbuf, principal, strlen(principal)) ||
	  buf_putint(commitbuf, kvno)) {
	SSL_shutdown(ssl);
	fatal("Internal error: Cannot append to buffer");
      } 
      resp = sendrcv(ssl, OP_COMMITKEY, commitbuf);
      if (resp == RESP_ERR) {
	prt_err_reply(commitbuf);
      } else if (resp == RESP_FATAL) {
	prt_err_reply(commitbuf);
	/* this connection is dead (don't send any more messages)*/
	no_send=1; 
	/* ....but keep processing the keys we received */
      } else if (resp != RESP_OK) {
	prtmsg("Unexpected reply type %d from server", resp);
      }
    }
    krb5_free_principal(ctx, ent.principal);
    memset(&ent, 0, sizeof(ent));
  }
 out:
  free(principal);
  buf_free(buf);
  buf_free(commitbuf);
  if (kt)
    krb5_kt_close(ctx, kt);
  if (ctx) {
    if (ent.principal)
      krb5_free_principal(ctx, ent.principal);
    krb5_free_context(ctx);
  }
  if (no_send) {
    SSL_shutdown(ssl);
    fatal("Exiting due to previous errors");
  }
}
int main(int argc, char **argv) {
  SSL *conn;

  ssl_startup();

  conn=do_connect("sphinx.andrew.cmu.edu");
  do_auth(conn, "sphinx.andrew.cmu.edu");
  printf("Attach to remote server if required, then press return\n");
  getc(stdin);
  if (argc > 2)
    do_newreq(conn, argv[1], 0, argc - 2, argv + 2);
  else if (argc == 2)
    do_status(conn, argv[1]);
  else 
    do_getkeys(conn);
    
  SSL_shutdown(conn);
  SSL_free(conn);
  return 0;
}
