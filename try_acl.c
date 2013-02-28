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

#define SESS_PRIVATE
#include "rekeysrv-locl.h"

char *builtin_acl[] = {
  "foo@REKEY.EXAMPLE",
  "bar@REKEY.EXAMPLE",
  "!bar@REKEY.EXAMPLE",
  "!baz@REKEY.EXAMPLE",
  "baz@REKEY.EXAMPLE",
  "!foo/bar@REKEY.EXAMPLE",
  "*/*@REKEY.EXAMPLE",
  NULL
};

void vprtmsg(const char *msg, va_list ap) {
     vfprintf(stderr, msg, ap);
     fputs("\n", stderr);
}

int krealm_init(struct rekey_session *sess) {
  return 0;
}

static struct rekey_session *setup_session(void)
{
  struct rekey_session *sess;

  if (!(sess = calloc(1, sizeof(struct rekey_session))))
    fatal("Out of memory!");

  if (krb5_init_context(&sess->kctx))
    fatal("krb5_init_context failed");

  if (krb5_get_default_realm(sess->kctx, &sess->realm))
    fatal("krb5_get_default_realm failed");

  return sess;
}

static void usage(void)
{
  fputs("Usage: try_acl b[e] <subj>         test subj against builtin acl\n"
        "       try_acl f[e] <file> <subj>  test subj against file\n"
        "       try_acl s[e] <pat> <subj>   test subj against pattern\n"
        "       try_acl o <file>            print builtin acl to file\n",
        stderr);
  exit(2);
}

int main(int argc, char **argv)
{
  struct rekey_session *sess;
  krb5_principal subject;
  struct ACL *acl;
  FILE *F;
  char *string_acl[3], **x;
  int rc, exact = 0;

  if (argc < 2) usage();

  switch ((*++argv)[0]) {
    case 'b':
      if (argc < 3) usage();
      exact = ((*argv)[1] == 'e');
      sess = setup_session();
      acl = acl_load_builtin(sess, "<builtin>", builtin_acl);
      break;

    case 'f':
      if (argc < 4) usage();
      exact = ((*argv)[1] == 'e');
      sess = setup_session();
      acl = acl_load(sess, *++argv);
      break;

    case 's':
      if (argc < 4) usage();
      exact = ((*argv)[1] == 'e');
      sess = setup_session();
      string_acl[0] = *++argv;
      if (**argv == '!') {
        string_acl[1] = "**@REKEY.EXAMPLE";
        string_acl[2] = 0;
      } else {
        string_acl[1] = 0;
      }
      acl = acl_load_builtin(sess, "<string>", string_acl);
      break;

    case 'o':
      if (argc < 3) usage();
      if (!(F = fopen(*++argv, "w")))
        fatal("%s: %s\n", *argv, strerror(errno));
      for (x = builtin_acl; *x; x++)
        fprintf(F, "%s\n", *x);
      fclose(F);
      exit(0);

    default: usage();
  }

  if ((rc = krb5_parse_name(sess->kctx, *++argv, &subject)))
    fatal("%s: %s\n", *argv, krb5_get_err_text(sess->kctx, rc));

  rc = acl_check(sess, acl, subject, exact);
  exit(rc ? 0 : 99);
}
