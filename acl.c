/*
 * Copyright (c) 2013 Carnegie Mellon University.  All rights reserved.
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
#include <stdio.h>
#include <ctype.h>

#define SESS_PRIVATE
#define NEED_KRB5
#include "rekeysrv-locl.h"
#include "rekey-locl.h"

struct ACL {
  struct ACL *next;
  int negative;
  krb5_principal pattern;
};

#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)

/* Returns 1 iff subject matches pattern, component-wise */
static int pattern_match(krb5_context ctx, char *lrealm,
                         krb5_principal subject, krb5_principal pattern)
{
  const char *scomp, *pcomp;
  int i;

  /*
   * The realms must match exactly, or the pattern realm must be "*".
   * If the pattern realm is missing, the local realm is used.
   * It is an error (failed match) for the subject realm to be missing.
   */
  scomp = krb5_principal_get_realm(ctx, subject);
  pcomp = krb5_principal_get_realm(ctx, pattern);
  if (!pcomp)
    pcomp = lrealm;
  if (!scomp || (strcmp(pcomp, "*") && strcmp(pcomp, scomp)))
    return 0;

  for (i = 0;; i++) {
    scomp = krb5_principal_get_comp_string(ctx, subject, i);
    pcomp = krb5_principal_get_comp_string(ctx, pattern, i);
    /*
     * If we hit the ends of both subject and pattern at the same time,
     * the match is successful.  Otherwise, if we hit the end of either,
     * then they are different lengths and the match fails.  The only
     * exception is that if the _last_ pattern component is "**", then
     * the match succeeds as soon as that component is encountered,
     * regardless of how many components are left in the subject.
     *
     * Otherwise, each component must match, which means either they
     * compare identical or the pattern component is exactly "*".
     */
    if (!scomp && !pcomp) return 1;
    if (!scomp || !pcomp) return 0;
    if (!strcmp(pcomp, "**") &&
        !krb5_principal_get_comp_string(ctx, pattern, i+1))
      return 1;

    if (strcmp(pcomp, "*") && strcmp(pcomp, scomp))
      return 0;
  }
  /* We should never get here! */
  return 0;
}

#elif defined(KRB5_PRINCIPAL_MIT_STYLE)

/* Returns 1 iff component <key> matches component pattern <pat>. */
static int kdcmp(krb5_data key, krb5_data pat)
{
  if (pat->length == 1 && pat->data[0] == '*') return 1;
  if (pat->length != key->length) return 0;
  return !memcpy(pat->data, key->data, pat->length);
}

/* Returns 1 iff subject matches pattern, component-wise */
static int pattern_match(krb5_context ctx, char *lrealm,
                         krb5_principal subject, krb5_principal pattern)
{
  krb5_data *scomp, *pcomp, lrealm_data;
  int i, slen, plen;

  /*
   * The realms must match exactly, or the pattern realm must be "*".
   * If the pattern realm is missing, the local realm is used.
   * It is an error (failed match) for the subject realm to be missing.
   */
  scomp = krb5_princ_realm(ctx, subject);
  pcomp = krb5_princ_realm(ctx, pattern);
  if (!pcomp) {
    lrealm_data.data = lrealm;
    lrealm_data.length = strlen(lrealm);
    pcomp = &lrealm_data;
  }
  if (!scomp || !kdcmp(scomp, pcomp))
    return 0;

  slen = krb5_princ_size(subject);
  plen = krb5_princ_size(pattern);
  for (i = 0; i < slen && i < plen; i++) {
    scomp = krb5_princ_component(ctx, subject, i);
    pcomp = krb5_princ_component(ctx, pattern, i);
    /*
     * Special case: if the _last_ pattern component is "**", then
     * the match succeeds as soon as that component is encountered,
     * regardless of how many components are left in the subject.
     */
    if (pcomp->length == 2 && !strncmp(pcomp->data, "**", 2))
      return 1;

    /*
     * Otherwise, each component must match, which means either they
     * compare identical or the pattern component is exactly "*".
     */
    if (!kdcmp(scomp, pcomp))
      return 0;
  }
  /*
   * If we hit the ends of both subject and pattern at the same time,
   * the match is successful.  Otherwise, if we hit the end of either,
   * then they are different lengths and the match fails.
   */
  if (slen == plen)
    return 1;
  return 0;
}

#endif


struct ACL *acl_load(struct rekey_session *sess, char *file)
{
  char buf[BUFSIZ], *x, *y;
  struct ACL *acl = NULL, **next = &acl, *entry;
  FILE *F;
  int rc, line = 0;

  F = fopen(file, "r");
  if (!F)
    fatal("%s: %s", file, strerror(errno));

  while (fgets(buf, sizeof(buf), F)) {
    line++;
    for (x = buf; isspace(*x); x++);
    if (!*x || *x == '#') continue;
    for (y = x + strlen(x) - 1; y > x && isspace(*y); y--)
      *y = 0;
    if (!strcmp(x, "!")) {
      prtmsg("%s[%d]: Invalid empty negative ACL entry", file, line);
      continue;
    }

    entry = malloc(sizeof(struct ACL));
    if (!entry)
      fatal("%s[%d]: Out of memory\n", file, line);
    memset(entry, 0, sizeof(*entry));
    if (*x == '!') {
      entry->negative = 1;
      x++;
    }

    if ((rc = krb5_parse_name(sess->kctx, x, &entry->pattern))) {
      prtmsg("%s[%d]: %s", file, line, krb5_get_err_text(sess->kctx, rc));
      free(entry);
      continue;
    }

    *next = entry;
    next = &entry->next;
  }

  if (ferror(F))
    fatal("%s: %s", file, strerror(errno));
  fclose(F);
  return acl;
}


int acl_check(struct rekey_session *sess, struct ACL *acl,
              krb5_principal subject, int exact)
{
  int match;

  if (krealm_init(sess))
    return 0;
  while (acl) {
    if (exact)
      match = krb5_principal_compare(sess->kctx, subject, acl->pattern);
    else
      match = pattern_match(sess->kctx, sess->realm, subject, acl->pattern);

    if (match)
      return !acl->negative;

    acl = acl->next;
  }
  return 0;
}
