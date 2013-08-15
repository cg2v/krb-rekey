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
#include <getopt.h>
#include <openssl/ssl.h>
#ifdef USE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#include "memmgt.h"
#include "protocol.h"
#include "rekey-locl.h"
#include "rekeyclt-locl.h"

int main(int argc, char **argv) {
  SSL *conn;
  char *keytab = "tmp.keytab";
  char *servername = "rekey.andrew.cmu.edu";
  char *princname = REKEY_DEF_SERVICE;
  int optch;
  int flag=0;

  while ((optch = getopt(argc, argv, "k:s:P:d")) != -1) {
    switch (optch) {
    case 'k':
      keytab = optarg;
      break;
    case 's':
      servername = optarg;
      break;
    case 'P':
      princname = optarg;
      break;
    case 'd':
      flag|=REQFLAG_DESONLY;
      break;
    case '?':
      fprintf(stderr, "Usage: rekeytest [-k keytab] [-r realm] [-s servername] [-P serverprinc]\n [-d] [princ [hostname...] \n");
      exit(1);
    }
  }

  ssl_startup();

  conn=c_connect(servername);
  printf("Attach to remote server if required, then press return\n");
  getc(stdin);
  c_auth(conn, servername, princname);
  if (argc > 2)
    c_newreq(conn, argv[1], flag, argc - 2, argv + 2);
  else if (argc == 2)
    c_status(conn, argv[1]);
  else 
    c_getkeys(conn, keytab, 0, NULL, 0);
    
  SSL_shutdown(conn);
  SSL_free(conn);
  ssl_cleanup();
  return 0;
}
