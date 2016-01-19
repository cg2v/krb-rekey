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
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define SESS_PRIVATE
#define NEED_SSL
#include "rekeysrv-locl.h"

#include <openssl/dh.h>
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif
#else
#define OPENSSL_NO_EC
#endif

#include "memmgt.h"

static SSL_CTX *sslctx;

#include "dhp7680.h"

static DH *get_dh(SSL *ssl, int is_export, int keysize) {
  DH *ret;
  if (is_export || keysize < 512 || keysize > 7680)
    ret = NULL;
  else
    ret = get_dh7680();
  return ret;
}

#ifndef OPENSSL_NO_EC
static EC_KEY *get_ecdh(SSL *ssl, int is_export, int keysize) {
  EC_KEY *ret;
  if (is_export || keysize < 512 || keysize > 7680)
    ret = NULL;
  else
    ret = EC_KEY_new_by_curve_name(NID_secp384r1);
  return ret;
}
#endif
void ssl_startup(void) {
  int rc;
  SSL_library_init();
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  
  sslctx=SSL_CTX_new(SSLv23_server_method());
  if (!sslctx)
    ssl_fatal(NULL, 0);
  rc=SSL_CTX_set_cipher_list(sslctx, "aNULL:-eNULL:-EXPORT:-LOW:-MD5:@STRENGTH");
  if (rc == 0)
    ssl_fatal(NULL, 0);
  SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_tmp_dh_callback(sslctx, get_dh);
#ifndef OPENSSL_NO_EC
  SSL_CTX_set_tmp_ecdh_callback(sslctx, get_ecdh);
#endif
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
static int listenfds[16];
static int nlfds;

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

void net_startup(void) {
  struct addrinfo ahints, *conn, *p;
  int i, s, rc;
  int on=1;

  memset(&ahints, 0, sizeof(ahints));
  ahints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
  ahints.ai_family = PF_UNSPEC;
  ahints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(NULL, "4446", &ahints, &conn);
  if (rc)
    fatal("socket setup failed: %s", gai_strerror(rc));

  for (i=0, p=conn; p; p=p->ai_next) {
    s=socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (s < 0)
      continue;
#ifdef IPV6_V6ONLY
    /* otherwise v4 connections come in on V4MAPPED ipv6 sockets and look
       messy */
    if (p->ai_family == PF_INET6) {
      setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    
    if (bind(s, p->ai_addr, p->ai_addrlen)) {
      close(s);
      continue;
    }
    if (listen(s, 16)) {
      close(s);
      continue;
    }
    rc = fcntl(s, F_GETFL);
    if (rc == -1) {
         close(s);
         continue;
    }
    if (fcntl(s, F_SETFL, rc | O_NONBLOCK)) {
      close(s);
      continue;
    }
    listenfds[i++]=s;
    if (i >= 15)
      break;
  }
  if (i == 0)
    fatal("Could not set up any sockets: %s", strerror(errno));
  nlfds = i;
}


SSL *do_ssl_accept(int s) {
  SSL *ret;
  int rc;

  if (!sslctx)
    fatal("SSL not initialized");  
  ret=SSL_new(sslctx);
  if (!ret)
    ssl_fatal(NULL, 0);
  
  rc=SSL_set_fd(ret, s);
  if (rc == 0)
    ssl_fatal(ret, rc);
  
  rc=SSL_accept(ret);
  if (rc != 1)
    ssl_fatal(ret, rc); /* probably wrong */
  
  return ret;
}

void child_cleanup(void) 
{
  int i;
  for (i=0;i<nlfds;i++) {
    close(listenfds[i]);
    listenfds[i]=-1;
  }
  if (sslctx)
    SSL_CTX_free(sslctx);
  sslctx=NULL;
}

int run_accept_loop(void (*cb)(int , struct sockaddr *))
{
  struct pollfd fdp[16];
  int rc, i, s, fails=0;
  
  for (i=0; i<nlfds; i++) {
    fdp[i].fd = listenfds[i];
    fdp[i].events = POLLIN;
  }
  for (;;) {
    rc = poll(fdp, nlfds, -1);
    if (rc < 0) {
      if (fails++ > 5)
       fatal("poll failed: %s", strerror(errno));
      continue;
    }
    fails=0;
    for (i=0; i<nlfds; i++) {
      if (fdp[i].revents & POLLIN) {
       struct sockaddr_storage ss;
       struct sockaddr *sa = (struct sockaddr *)&ss;
       socklen_t ssz;
       ssz=sizeof(ss);
       while ((s=accept(fdp[i].fd, sa, &ssz)) > 0) {
         rc = fcntl(s, F_GETFL);
          if (rc == -1) {
            close(s);
            continue;
          }
          if (fcntl(s, F_SETFL, rc & (~O_NONBLOCK))) {
            close(s);
            continue;
          }
         cb(s, sa);
         ssz=sizeof(ss);
       }
      }
    }
  }
}
