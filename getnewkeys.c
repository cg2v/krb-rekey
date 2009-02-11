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
#include <getopt.h>
#include <openssl/ssl.h>
#ifdef HEADER_GSSAPI_GSSAPI
#include <gssapi/gssapi.h>
#else
#include <gssapi.h>
#endif

#include "memmgt.h"
#include "rekey-locl.h"
#include "rekeyclt-locl.h"
#include "protocol.h"

int main(int argc, char **argv) {
  SSL *conn;
  char *realm=NULL;
  char *servername=NULL;
  char *keytab=NULL;
  int optch;
  
  while ((optch = getopt(argc, argv, "k:r:s:")) != -1) {
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
    case '?':
      fprintf(stderr, "Usage: getnewkeys [-k keytab] [-r realm] [-s hostname]\n");
      exit(1);
    }
  }
  ssl_startup();
  if (!servername)
    servername = get_server(realm);
  conn = c_connect(servername);
  c_auth(conn, servername);
  printf("Attach to remote server if required, then press return\n");
  getc(stdin);
  c_getkeys(conn, keytab);
  c_close(conn);
  ssl_cleanup();
  return 0;
}