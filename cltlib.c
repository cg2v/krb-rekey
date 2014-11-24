/*
 * Copyright (c) 2008-2009, 2013 Carnegie Mellon University.
 * All rights reserved.
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
#include <ctype.h>
#include <limits.h>
#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif
#ifdef USE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "memmgt.h"
#include "rekey-locl.h"
#include "rekeyclt-locl.h"
#include "protocol.h"
#include "krb5_portability.h"

static SSL_CTX *sslctx;

void vprtmsg(const char *msg, va_list ap) {
     vfprintf(stderr, msg, ap);
     fputs("\n", stderr);
}

void ssl_startup(void) {
  int rc;
     SSL_library_init();
     ERR_load_crypto_strings();
     ERR_load_SSL_strings();
     
     sslctx=SSL_CTX_new(TLSv1_client_method());
     if (!sslctx)
       ssl_fatal(NULL, 0);
     rc=SSL_CTX_set_cipher_list(sslctx, "aNULL:-eNULL:-EXPORT:-LOW:-MD5:@STRENGTH");
     if (rc == 0)
       ssl_fatal(NULL, 0);
}

void ssl_cleanup(void) {
  if (sslctx)
    SSL_CTX_free(sslctx);
  sslctx=NULL;
  EVP_cleanup();
  ERR_free_strings();
#ifdef HAVE_CRYPTO_CLEANUP_ALL_EX_DATA
  CRYPTO_cleanup_all_ex_data();
#endif
}
void c_close(SSL *ssl) {
  SSL_shutdown(ssl);
  SSL_free(ssl);
}

char *get_server(char *realm) {
  krb5_context ctx;
  static char *ret=NULL;
  char *intrealm=NULL;
  int i;

  if (krb5_init_context(&ctx))
    fatal("Cannot initialize krb context");
  if (!realm) {
    if (krb5_get_default_realm(ctx, &intrealm))
      fatal("Cannot get default kerberos realm");
    realm=intrealm;
  }
  ret = malloc(6+ strlen(realm) + 1);
  if (!ret)
    goto out;
  sprintf(ret, "rekey.%s", realm);
  for (i=0;i<strlen(ret);i++) {
    if (isalpha((unsigned char)ret[i]) && isupper((unsigned char)ret[i]))
      ret[i]=tolower((unsigned char)ret[i]);
  }
 out:
  if (intrealm) {
#ifdef HAVE_KRB5_REALM
    krb5_xfree(realm);
#else
    krb5_free_default_realm(ctx, realm);
#endif
  }
  krb5_free_context(ctx);
  return ret;
}

#if defined(HAVE_KRB5_KTF_WRITABLE_OPS) && !HAVE_DECL_KRB5_KTF_WRITABLE_OPS
extern krb5_kt_ops krb5_ktf_writable_ops;
#endif

krb5_keytab get_keytab(krb5_context ctx, char *keytab) 
{
  krb5_keytab kt=NULL;
  char *ktdef=NULL, *ktname=NULL;
  int rc;

  if (!keytab) {
    ktdef=malloc(BUFSIZ);
    if (!ktdef) {
      fatal("Memory allocation failed: %s", strerror(errno));
    } 
    rc = krb5_kt_default_name(ctx, ktdef, BUFSIZ);
    if (rc) {
      prtmsg("krb5_kt_default_name failed (%s)", krb5_get_err_text(ctx, rc));
      goto out;
    }   
    keytab = ktdef;
  }
  
  if (!strncmp(keytab, "FILE:", 5)) {
    keytab=&keytab[5];
    goto is_file;
  }
  if (!strchr(keytab, ':')) {
is_file:
    ktname = malloc(8 + strlen(keytab));
    if (!ktname) {
      fatal("Memory allocation failed: %s", strerror(errno));
    } 
    sprintf(ktname, "WRFILE:%s", keytab);
    rc = krb5_kt_resolve(ctx, ktname, &kt);
    if (rc) {
#ifdef HAVE_KRB5_KTF_WRITABLE_OPS
      rc = krb5_kt_register(ctx, &krb5_ktf_writable_ops);
      if (rc != 0 || (rc = krb5_kt_resolve(ctx, ktname, &kt))) {
#endif
	sprintf(ktname, "FILE:%s", keytab);
	rc = krb5_kt_resolve(ctx, ktname, &kt);
	if (rc) {
	  prtmsg("krb5_kt_resolve failed (%s)", krb5_get_err_text(ctx, rc));
	  goto out;
	}
#ifdef HAVE_KRB5_KTF_WRITABLE_OPS
      }
#endif
    } 
  } else {
    rc = krb5_kt_resolve(ctx, keytab, &kt);
    if (rc) {
      prtmsg("krb5_kt_resolve failed (%s)", krb5_get_err_text(ctx, rc));
      goto out;
    }
  }
 out:
  free(ktdef);
  free(ktname);
  return kt;
}


int get_keytab_targets(char *keytab, int *n, char ***out) 
{
  krb5_context ctx;
  krb5_keytab kt;
  krb5_kt_cursor kc;
  krb5_error_code rc;
  int alloc, cur=0, i, opened=0;
  char **princs=NULL, **new, *name=NULL;
  krb5_keytab_entry ent;
  
  if ((rc=krb5_init_context(&ctx))) {
    prtmsg("krb5_init_context failed: %d", rc);
    return 1;
  }
  kt = get_keytab(ctx, keytab);
  if (!kt)
    goto freeall;
  alloc=5;
  princs=malloc(alloc * sizeof(char *));
  if (!princs) {
    prtmsg("Memory allocation failed listing keytab");
    goto freeall;
  }
  
  rc = krb5_kt_start_seq_get(ctx, kt, &kc);
  if (rc) {
    prtmsg("cannot open keytab: %s", krb5_get_err_text(ctx, rc));
    goto freeall;
  }
  opened=1;
  while (0 == (rc = krb5_kt_next_entry(ctx, kt, &ent, &kc))) {
    rc = krb5_unparse_name(ctx, ent.principal, &name);
    if (rc) {
      prtmsg("Warning: cannot get name string from keytab: %s", krb5_get_err_text(ctx, rc));
      krb5_free_keytab_entry_contents(ctx, &ent);
      
      continue;
    }
    for (i=0;i < cur; i++)
      if (!strcmp(name, princs[i]))
        break;
    if (i < cur) {
#if HAVE_DECL_KRB5_FREE_UNPARSED_NAME
      krb5_free_unparsed_name(ctx, name);
#else
      krb5_xfree(name);
#endif
      continue;
    }
    if (i >= alloc) {
      alloc+=5;
      new=realloc(princs, alloc * sizeof(char *));
      if (!new) {
	prtmsg("Memory allocation failed listing keytab");
	goto freeall;
      }
      princs=new;
    }
    princs[cur]=strdup(name);
#if HAVE_DECL_KRB5_FREE_UNPARSED_NAME
    krb5_free_unparsed_name(ctx, name);
#else
    krb5_xfree(name);
#endif

    if (!princs[cur]) {
      prtmsg("Memory allocation failed listing keytab");
      goto freeall;
    }
    cur++;
  }
  krb5_kt_end_seq_get(ctx, kt, &kc);
  
  if (rc != KRB5_KT_END)
    prtmsg("Warning: strange result while reading from keytab: %s", krb5_get_err_text(ctx, rc));
  krb5_kt_close(ctx, kt);
  krb5_free_context(ctx);
  *n=cur;
  *out=princs;
  return 0;
 freeall:
  if (opened)
    krb5_kt_end_seq_get(ctx, kt, &kc);
  if (kt)
    krb5_kt_close(ctx, kt);
  krb5_free_context(ctx);
  for (i=0;i<cur;i++)
    free(princs[i]);
  free(princs);
  return 1;
}
/* glibc 2.3.3 and solaris 8 don't define AI_NUMERICSERV, but will accept a
   numeric service anyway. gnulib's getaddrinfo.h/netdb.h supplies a
   definitition even if the
   gnulib getaddrinfo implementation doesn't get used. the gnulib implementation does not provide/implement AI_ADDRCONFIG, so zero that if it's not defined
 */
#if AI_NUMERICSERV > 128
#ifdef AI_ADDRCONFIG
/* assume native getaddrinfo will be used */
#undef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#else
/* assume gnulib getaddrinfo will be used */
#define AI_ADDRCONFIG 0
#endif
#endif

SSL *c_connect(char *hostname) {
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

int sendrcv(SSL *ssl, int opcode, mb_t data) {
  int ret;
  do_send(ssl, opcode, data);
  ret=do_recv(ssl, data);
  if (ret == -1) {
     c_close(ssl);
     fatal("Unexpected server failure: connection closed");
  }
  return ret;
}

void c_auth(SSL *ssl, char *hostname, char *svcname) {
 unsigned char *p;
     
 OM_uint32 maj, min, rflag;
 gss_name_t n=NULL;
 gss_ctx_id_t gctx=GSS_C_NO_CONTEXT;
 gss_buffer_desc inname, in, out;
 gss_buffer_t inp=GSS_C_NO_BUFFER;
 gss_OID_desc reqmech;
 gss_OID mech;
 int gss_more_init=1,gss_more_accept=1, flen;
 int resp=0;
 mb_t mic;
 gss_qop_t qop;
     
 char namebuf[256];
     
 if (svcname && *svcname && strcmp(svcname, "-")) {
   inname.value=svcname;
   inname.length=strlen(svcname);

   maj = gss_import_name(&min, &inname, GSS_KRB5_NT_PRINCIPAL_NAME, &n);

 } else {
   memset(namebuf, 0, 256);
   snprintf(namebuf, 255, "host@%s", hostname);

   inname.value=namebuf;
   inname.length=strlen(namebuf);

   maj = gss_import_name(&min, &inname, GSS_C_NT_HOSTBASED_SERVICE, &n);
 }
     
 if (GSS_ERROR(maj)) {
   prt_gss_error(GSS_C_NO_OID, maj, min);
   c_close(ssl);
   fatal("Cannot authenticate");
 }
     
 memset(&out, 0, sizeof(out));
 reqmech.length = gss_mech_krb5->length;
 reqmech.elements = malloc(reqmech.length);
 if (!reqmech.elements) {
   c_close(ssl);
   fatal("Cannot allocate memory");
 }   
 memcpy(reqmech.elements, gss_mech_krb5->elements, reqmech.length);
 do {
   /* can't use GSS_C_NO_OID with GSS_C_NO_CREDENTIAL on solaris */
   /* Should be using gss_indicate_mechs and iterating, but
      that would require major refactoring of this function, and it
      is questionable whether the server would deal correctly,
      especially as it currently exits after receiving OP_AUTHERR */
   maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &gctx,
                              n, &reqmech, 
                              GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG,
                              GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                              inp, &mech, &out, &rflag, NULL);
   if (inp) {
     free(inp->value);
     inp->value=0;
   }
   if (GSS_ERROR(maj)) {
     prt_gss_error(mech ? mech : &reqmech, maj, min);
     gss_more_init=0;
   } else {
     if (!(maj & GSS_S_CONTINUE_NEEDED)) {
       gss_more_init=0;
     } else {
       if (out.length == 0) {
         c_close(ssl);
         fatal("Authentication failed: not sending a gss token but expects a reply");
       }
     }
   }
   if (resp == RESP_AUTHERR) {
     c_close(ssl);
     exit(1);
   }
   
   if (out.length && gss_more_accept == 0) {
     c_close(ssl);
     fatal("Authentication failed: would send a gss token when remote does not expect one");
   }
   
   if (out.length) {
     mb_t auth;
     OM_uint32 f;
     unsigned int l;

     auth = buf_alloc(out.length + 8);
     if (auth == NULL) {
       c_close(ssl);
       fatal("Cannot authenticate: memory allocation failed: %s",
             strerror(errno));
     }
             
     f=0;
     if (gss_more_init) f|=AUTHFLAG_MORE;
     if (buf_appendint(auth, f) || 
	 buf_appendint(auth, out.length) ||
	 buf_appenddata(auth, out.value, out.length)) {
       c_close(ssl);
       fatal("internal error: cannot pack authentication structure");
     }
     gss_release_buffer(&min, &out);
     resp = sendrcv(ssl, GSS_ERROR(maj) ? OP_AUTHERR : OP_AUTH, auth);
     if (resp == RESP_ERR || resp == RESP_FATAL) {
       c_close(ssl);
       prt_err_reply(auth);
       exit(1);
     }
     if (resp == RESP_OK) {
       buf_free(auth);
       if (gss_more_init) {
         c_close(ssl);
         fatal("Cannot authenticate: server did not send authentication reply");
       }
       gss_more_accept = 0;
     } else {
       if (resp == RESP_AUTH || resp == RESP_AUTHERR) {
	 reset_cursor(auth);
         if (buf_getint(auth, &f) ||
	     buf_getint(auth, &l)) {
	   c_close(ssl);
	   fatal("Cannot authenticate: server sent malformed reply");
	 }   
         in.length=l;
	 in.value=malloc(in.length);
	 if (in.value == NULL) {
	   c_close(ssl);
	   fatal("Cannot authenticate: memory allocation failed: %s",
             strerror(errno));
	 }
	 if (buf_getdata(auth, in.value, in.length)) {
	   c_close(ssl);
	   fatal("Cannot authenticate: server sent malformed reply");
	 }   
	 buf_free(auth);
	 if (resp == RESP_AUTH && (f & AUTHFLAG_MORE))
           gss_more_accept = 1;
         else
           gss_more_accept = 0;

         inp = &in;
       } else {
         c_close(ssl);
         fatal("Cannot authenticate: server sent unexpected response %d", resp);
       }                    
     }       
   }
   if (GSS_ERROR(maj)) {
     c_close(ssl);
     exit(1);
   }
 } while (gss_more_init);
 if ((~rflag) & (GSS_C_MUTUAL_FLAG|GSS_C_INTEG_FLAG)) {
   c_close(ssl);
   fatal("GSSAPI mechanism does not provide data integrity services");
 }

 flen = SSL_get_finished(ssl, NULL, 0);
 if (flen == 0) {
   c_close(ssl);
   fatal("Cannot authenticate: ssl finished message not available");
 }    
 in.length = 2 * flen;
 in.value = malloc(in.length);
 if (in.value == NULL) {
   c_close(ssl);
   fatal("Cannot authenticate: memory allocation failed: %s",
         strerror(errno));
 }
 p=in.value;
 if (flen != SSL_get_finished(ssl, p, flen)) {
   c_close(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_peer_finished(ssl, p, flen)) {
   c_close(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }
     
 maj = gss_get_mic(&min, gctx, GSS_C_QOP_DEFAULT, &in, &out);
 if (GSS_ERROR(maj)) {
   prt_gss_error(mech, maj, min);
   c_close(ssl);
   exit(1);
 }

  mic=buf_alloc(out.length);
  if (mic == NULL)
    fatal("Cannot allocate memory: %s", strerror(errno));
  if (buf_appenddata(mic, out.value, out.length)) {
    fatal("internal error: cannot pack authentication structure");
  }
  
  resp = sendrcv(ssl, OP_AUTHCHAN, mic);
  if (resp == RESP_ERR || resp == RESP_FATAL) {
   c_close(ssl);
   prt_err_reply(mic);
   exit(1);
 }
 if (resp != RESP_AUTHCHAN) {
   c_close(ssl);
   fatal("Cannot authenticate: server sent unexpected response %d", 
         resp);
 }
 gss_release_buffer(&min, &out);
 out.length = mic->length;
 out.value = mic->value;

 p=in.value;
 if (flen != SSL_get_peer_finished(ssl, p, flen)) {
   c_close(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_finished(ssl, p, flen)) {
   c_close(ssl);
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 maj = gss_verify_mic(&min, gctx, &in, &out, &qop);
 buf_free(mic);
 if (maj == GSS_S_BAD_SIG) {
   c_close(ssl);
   fatal("channel binding verification failed (signature does not match)");
 }
     
 if (GSS_ERROR(maj)) {
   prt_gss_error(mech, maj, min);
   c_close(ssl);
   exit(1);
 }
 free(in.value);
 free(reqmech.elements);
 gss_delete_sec_context(&min, &gctx, GSS_C_NO_BUFFER);
 gss_release_name(&min, &n);
}

void c_newreq(SSL *ssl, char *princ, int flag, int nhosts, char **hosts) 
{
  mb_t buf;
  int i, resp;
  
  if (nhosts < 1) {
    prtmsg("Host list is empty");
    return;
  }
  buf = buf_alloc(4 + strlen(princ) + 4 + 4 + nhosts * (4 + strlen(hosts[0])));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  if (buf_appendstring(buf, princ) ||
      buf_appendint(buf, flag) ||
      buf_appendint(buf, nhosts)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  for (i=0;i<nhosts;i++) {
    if (buf_appendstring(buf, hosts[i])) {
      c_close(ssl);
      fatal("Cannot extend buffer: %s", strerror(errno));
    } 
  }
  resp = sendrcv(ssl, OP_NEWREQ, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
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

void c_status(SSL *ssl, char *princ) {
  mb_t buf;
  unsigned int f, i, n, resp, t;
  char *hostname;
  int kvno;

  buf = buf_alloc(4 + strlen(princ));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  if (buf_appendstring(buf, princ)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_STATUS, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
    exit(1);
  }
  if (resp != RESP_STATUS) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
  reset_cursor(buf);
  if (buf_getint(buf, &f) ||
      buf_getint(buf, &t) ||
      buf_getint(buf, &n)) {
    prtmsg("Server sent malformed reply");
    goto out;
  }
  if (t > INT_MAX) {
    prtmsg("kvno is too large for signed int!");
    kvno=-1;
  } else {
    kvno=t;
  }

  if (f != 0)
    prtmsg("Unknown flags 0x%x received", f);
  prtmsg("Rekey in progress; new kvno will be %d", kvno);
  if (n == 0)
    prtmsg("No hosts in access list -- direct rekey in progress");
    
  for (i=0; i<n; i++) {
    if (buf_getint(buf, &f) ||
        buf_getstring(buf, &hostname, malloc)) {
      prtmsg("Server sent malformed reply (or memory allocation failure)");
      goto out;
    }
    prtmsg("Host %s has%s finished rekeying for this principal",
           hostname, (f & STATUSFLAG_COMPLETE) ? "" : " not");
    if ((f & (STATUSFLAG_COMPLETE|STATUSFLAG_ATTEMPTED)) == STATUSFLAG_ATTEMPTED)
      prtmsg("Host %s has downloaded this key", hostname);
    free(hostname);
  }
 out:
  buf_free(buf);
}

static int scan_for_bad_keys(krb5_context ctx, mb_t buf) {
#if defined(BROKEN_ENCTYPE_VALIDITY) || \
  (! HAVE_DECL_KRB5_C_VALID_ENCTYPE && ! HAVE_DECL_KRB5_ENCTYPE_VALID)
  return 0;
#else
  unsigned int m, n, l, i, j, et, kvno; 
  char *principal=NULL;

  reset_cursor(buf);  
  if (buf_getint(buf, &m)) {
    prtmsg("Server sent malformed reply");
    goto out;
  }
  for (i=0; i < m; i++) {
    if (buf_getstring(buf, &principal, malloc)) {
      prtmsg("Server sent malformed reply (or memory allocation failed)");
      goto out;
    } 
    if (buf_getint(buf, &kvno) ||
	buf_getint(buf, &n)){
      prtmsg("Server sent malformed reply");
      goto out;
    } 
    for (j=0; j < n; j++) {
      if (buf_getint(buf, &et) ||
	  buf_getint(buf, &l)) {
	prtmsg("Server sent malformed reply");
	goto out;
      } 
      if (krb5_enctype_valid(ctx, et) != ENCTYPE_VALID && et != 2) {
	prtmsg("Principal %s has a new key with enctype %u, but this implementation does not support it", principal, et);
	goto out;
      }
      buf->cursor+=l;
      continue;
    }
    free(principal);
    principal=NULL;
  }
  return 0;
 out:
  if (principal)
    free(principal);
  return 1;
#endif
}

static int process_keys(krb5_context ctx, krb5_keytab kt, mb_t buf, 
                        int (*complete)(void *rock, char *principal, int kvno),
                        void *rock) 
{
  krb5_keytab_entry ent;
  krb5_keyblock key;
  krb5_error_code rc;
  unsigned int m, n, l, i, j, no_send=0, 
    no_send_single, skip, kvno, et;
  char *principal=NULL;
  
  memset(&ent, 0, sizeof(ent));
  reset_cursor(buf);
  
  if (buf_getint(buf, &m)) {
    prtmsg("Server sent malformed reply");
    goto out;
  }
  for (i=0; i < m; i++) {
    if (buf_getstring(buf, &principal, malloc)) {
      prtmsg("Server sent malformed reply (or memory allocation failed)");
      goto out;
    } 
    if (buf_getint(buf, &kvno) ||
	buf_getint(buf, &n)){
      prtmsg("Server sent malformed reply");
      goto out;
    } 
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
#if ( HAVE_DECL_KRB5_C_VALID_ENCTYPE || HAVE_DECL_KRB5_ENCTYPE_VALID) && \
  !defined(BROKEN_ENCTYPE_VALIDITY)
      /* skip des-cbc-md4 keys if they are not supported.
	 other unsupported enctypes cause the entire operation to be
	 aborted (ick) */
      if (et == 2 && krb5_enctype_valid(ctx, et) != ENCTYPE_VALID) {
	buf->cursor+=l;
	continue;
      }
#endif
      if (skip) {
	buf->cursor+=l;
	continue;
      }
      Z_enctype(&key)= et;
      Z_keylen(&key) = l;
      Z_keydata(&key) = malloc(l);
      if (!Z_keydata(&key)) {
	fatal("Memory allocation failed: %s", strerror(errno));
      } 
      if (buf_getdata(buf, Z_keydata(&key), l)) {
	free(Z_keydata(&key));
	prtmsg("Server sent malformed reply");
	goto out;
      }
      {
        krb5_keytab_entry cmpe;
        krb5_keyblock *cmp;
        krb5_enctype cmpet;
	int bad=0;

        memset(&cmpe, 0, sizeof(cmpe));
	rc = krb5_kt_get_entry(ctx, kt, ent.principal,
				      ent.vno, et, &cmpe);
	if (rc == 0) {
          cmp = kte_keyblock(&cmpe);
	  if (Z_enctype(&key) == Z_enctype(cmp) &&
	      (Z_keylen(&key) != Z_keylen(cmp) ||
	       memcmp(Z_keydata(&key), Z_keydata(cmp), Z_keylen(&key)))) {
	    bad=1;
	    prtmsg("This keytab has an entry for principal %s, kvno %u, enctype %u with a different key!", 
		   principal, kvno, et);
            rc = krb5_kt_remove_entry(ctx, kt, &cmpe);
	    if (rc) {
              prtmsg("krb5_kt_remove_entry failed (%s)", krb5_get_err_text(ctx, rc));
              goto out;
            }              
	  } 
	  cmpet = Z_enctype(cmp);
	  krb5_free_keytab_entry_contents(ctx, &cmpe);
	  /* don't add this new keytab entry if correct new key
	     is already present */
	  if (rc == 0 && bad == 0 && cmpet == et)
	    continue;
        }  
      }
      
      rc = krb5_copy_keyblock_contents(ctx, &key, kte_keyblock(&ent));
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
      krb5_free_keyblock_contents(ctx, kte_keyblock(&ent));
    }
    /* maybe close & reopen keytab? */
    if (skip == 0 && no_send == 0 && no_send_single == 0) {
      if (complete(rock, principal, kvno))
        no_send=1;
    }
    krb5_free_principal(ctx, ent.principal);
    memset(&ent, 0, sizeof(ent));
    free(principal);
    principal=NULL;
  }
 out:
  if (ent.principal)
    krb5_free_principal(ctx, ent.principal);
  free(principal);
  return no_send;
}


static int g_complete(void *vctx, char *principal, int kvno) 
{
  SSL *ssl = vctx;
  mb_t commitbuf;
  int resp;
  
  commitbuf=buf_alloc(8 + strlen(principal));
  if (!commitbuf) {
    c_close(ssl);
    fatal("Internal error: Cannot get new buffer: %s", strerror(errno));
  }

  if (buf_appendstring(commitbuf, principal) ||
      buf_appendint(commitbuf, kvno)) {
    c_close(ssl);
    fatal("Internal error: Cannot append to buffer");
  } 
  resp = sendrcv(ssl, OP_COMMITKEY, commitbuf);
  if (resp == RESP_ERR) {
    prt_err_reply(commitbuf);
  } else if (resp == RESP_FATAL) {
    prt_err_reply(commitbuf);
    /* this connection is dead (don't send any more messages)*/
    /* ....but keep processing the keys we received */
    buf_free(commitbuf);
    return 1;
  } else if (resp != RESP_OK) {
    prtmsg("Unexpected reply type %d from server", resp);
  }
  buf_free(commitbuf);
  return 0;
}


void c_getkeys(SSL *ssl, char *keytab, int nprincs, char **princs, int quiet) {
  krb5_context ctx=NULL;
  krb5_keytab kt=NULL;
  mb_t buf;
  int rc, resp, is_error=0, i;

  buf=buf_alloc(1);
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  rc = krb5_init_context(&ctx);
  if (rc) {
    prtmsg("krb5_init_context failed (%d)", rc);
    goto out;
  } 
  kt = get_keytab(ctx, keytab);
  if (!kt)
    goto out;  

  if (nprincs) {
    if (buf_appendint(buf, nprincs)) {
        c_close(ssl);
        fatal("Cannot extend buffer: %s", strerror(errno));
    }   
    for (i=0;i<nprincs;i++) {
      if (buf_appendstring(buf, princs[i])) {
        c_close(ssl);
        fatal("Cannot extend buffer: %s", strerror(errno));
      }
    }   
  }
  resp = sendrcv(ssl, OP_GETKEYS, buf);
  if (resp == RESP_ERR) {
    reset_cursor(buf);
    if (!quiet || (buf_getint(buf, &rc) || rc != ERR_NOKEYS))
      prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
    exit(1);
  }
  if (resp != RESP_KEYS) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
  is_error = scan_for_bad_keys(ctx, buf);
  if (is_error == 0)
    is_error = process_keys(ctx, kt, buf, g_complete, ssl);
  

 out:
  buf_free(buf);
  if (kt)
    krb5_kt_close(ctx, kt);
  if (ctx)
    krb5_free_context(ctx);
  if (is_error) {
    c_close(ssl);
    fatal("Exiting due to previous errors");
  }
}

void c_abort(SSL *ssl, char *princ) {
  mb_t buf;
  unsigned int resp;

  buf = buf_alloc(4 + strlen(princ));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  if (buf_appendstring(buf, princ)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_ABORTREQ, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
    exit(1);
  }
  if (resp != RESP_OK) {
    prtmsg("Unexpected reply type %d from server", resp);
    goto out;
  }
 out:
  buf_free(buf);
}

void c_finalize(SSL *ssl, char *princ) {
  mb_t buf;
  unsigned int resp;

  buf = buf_alloc(4 + strlen(princ));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  if (buf_appendstring(buf, princ)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_FINALIZE, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
    exit(1);
  }
  if (resp != RESP_OK) {
    prtmsg("Unexpected reply type %d from server", resp);
  }
 out:
  buf_free(buf);
}

static int count_complete(void *vctx, char *principal, int kvno)
{
  int *done=vctx;
  (*done)++;
  return 0;
}

void c_simplekey(SSL *ssl, char *princ, int flag, char *keytab) 
{
  mb_t buf;
  unsigned int resp, m;
  int done, rc;
  krb5_context ctx;
  krb5_keytab kt;
  char *principal=NULL;
  
  
  buf = buf_alloc(8 + strlen(princ));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 

  rc = krb5_init_context(&ctx);
  if (rc) {
    prtmsg("krb5_init_context failed (%d)", rc);
    buf_free(buf);
    return;
  } 
  kt = get_keytab(ctx, keytab);
  if (!kt)
    goto out;

  if (buf_appendstring(buf, princ) ||
      buf_appendint(buf, flag)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_SIMPLEKEY, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
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
  if (m != 1) {
    prtmsg("Too many keys (%d, not 1) in reply", m);
    goto out;
  }
  
  if (buf_getstring(buf, &principal, malloc)) {
    prtmsg("Server sent malformed reply (or memory allocation failed)");
    goto out;
  } 
  if (strcmp(princ, principal)) {
    prtmsg("Server response was for principal %s, not %s", principal, princ);
    goto out;
  }

  done=0;
  if (scan_for_bad_keys(ctx, buf) ||
      process_keys(ctx, kt, buf, count_complete, &done) || 
      done == 0)
    c_abort(ssl, princ);
  else
    c_finalize(ssl, princ);
 out:
  if (kt)
    krb5_kt_close(ctx, kt);
  if (ctx)
    krb5_free_context(ctx);
  free(principal);
  buf_free(buf);
}

void c_delprinc(SSL *ssl, char *princ) {
  mb_t buf;
  unsigned int resp;

  buf = buf_alloc(4 + strlen(princ));
  if (!buf) {
    c_close(ssl);
    fatal("Memory allocation failed: %s", strerror(errno));
  } 
  if (buf_appendstring(buf, princ)) {
    c_close(ssl);
    fatal("Cannot extend buffer: %s", strerror(errno));
  } 
  resp = sendrcv(ssl, OP_DELPRINC, buf);
  if (resp == RESP_ERR) {
    prt_err_reply(buf);
    goto out;
  }
  if (resp == RESP_FATAL) {
    prt_err_reply(buf);
    c_close(ssl);
    exit(1);
  }
  if (resp != RESP_OK) {
    prtmsg("Unexpected reply type %d from server", resp);
  }
 out:
  buf_free(buf);
}
