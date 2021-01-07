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
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <openssl/ssl.h>
#ifdef USE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#include "memmgt.h"
#include "rekey-locl.h"
#include "rekeyclt-locl.h"
#include "protocol.h"

#include <krb5.h>
#include "krb5_portability.h"

int main(int argc, char **argv) {
  SSL *conn;
  char *realm=NULL;
  char *targetname=NULL;
  char *servername=NULL;
  char *princname=REKEY_DEF_SERVICE;
  char *keytab=NULL;
  char *cmd;
  char **hostnames;
  int flag=REQFLAG_NODES;
  int optch;
  
  while ((optch = getopt(argc, argv, "k:r:s:P:dDA")) != -1) {
    switch (optch) {
    case 'k':
      keytab = optarg;
      break;
    case 'r':
      realm = optarg;
      break;
    case 's':
      servername = optarg;
      break;
    case 'P':
      princname = optarg;
      break;
    case 'd':
      flag|=REQFLAG_DESONLY;
    case 'D':
      flag &= ~REQFLAG_NODES;
      break;
    case 'A':
      flag|=REQFLAG_COMPAT_ENCTYPE;
      break;
    case '?':
      fprintf(stderr, "Usage: rekeymgr [-k keytab] [-r realm] [-s servername] [-P serverprinc]\n [-d|-D] [-A] command [args]\n");
      exit(1);
    }
  }

#if defined(BROKEN_ENCTYPE_VALIDITY) && !defined(HAVE_DECL_ENCTYPE_AES128_CTS_HMAC_SHA1_96) && \
  !defined(HAVE_DECL_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
  /* assume an old implementation */
  flag|=REQFLAG_COMPAT_ENCTYPE;
#else
  {
     krb5_context ctx;
     if (krb5_init_context(&ctx) == 0) {
       if (krb5_enctype_valid(ctx, 17) != ENCTYPE_VALID ||
           krb5_enctype_valid(ctx, 18) != ENCTYPE_VALID)
         flag|=REQFLAG_COMPAT_ENCTYPE;
       krb5_free_context(ctx);
     }
     if (krb5_init_context(&ctx) == 0) {
       if (krb5_enctype_valid(ctx, 16) != ENCTYPE_VALID ||
           krb5_enctype_valid(ctx, 23) != ENCTYPE_VALID)
         flag|=REQFLAG_COMPAT_ENCTYPE_RFC8429;
       krb5_free_context(ctx);
     }
  }
#endif
  cmd = argv[optind++];
  if (argc - optind < 1) {
    
  usage:
    fprintf(stderr, "Usage: rekeyclt [-k keytab] [-r realm] [-s servername] [-P serverprinc]\n [-d|-D] [-A] command [args]\n");
    fprintf(stderr, "       rekeyclt start principalname hostname [hostname]...\n");
    fprintf(stderr, "       rekeyclt status principalname\n");
    fprintf(stderr, "       rekeyclt abort principalname\n");
    fprintf(stderr, "       rekeyclt finalize principalname\n");
    fprintf(stderr, "       rekeyclt key principalname\n");
    exit(1);
  }
  targetname=argv[optind++];
  ssl_startup();
  if (!servername)
    servername = get_server(realm);
  conn = c_connect(servername);
  c_auth(conn, servername, princname);
#if 0
  printf("Attach to remote server if required, then press return\n");
  getc(stdin);
#endif

  if (!strcmp(cmd, "start")) {
    if (argc < optind)
      goto usage;
    hostnames = argv + optind;
    c_newreq(conn, targetname, flag, argc - optind, hostnames);
  } else if (!strcmp(cmd, "status")) {
    c_status(conn, targetname);
  } else if (!strcmp(cmd, "abort")) {
    c_abort(conn, targetname);
  } else if (!strcmp(cmd, "finalize")) {
    c_finalize(conn, targetname);
  } else if (!strcmp(cmd, "delprinc")) {
    c_delprinc(conn, targetname);
  } else if (!strcmp(cmd, "key")) {
    c_simplekey(conn, targetname, flag, keytab);
  } else {
    /*  fprintf(stderr, "??? unimplemented command %s\n", cmd);*/
    goto usage;
  }
  c_close(conn);
  ssl_cleanup();
  return 0;
}
