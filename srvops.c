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
#include <sys/syslog.h>
#include <sys/signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <groups.h>

#define SESS_PRIVATE
#define NEED_KRB5
#define NEED_GSSAPI
#define NEED_SQLITE
#include "rekeysrv-locl.h"
#include "rekey-locl.h"
#include "protocol.h"
#include "memmgt.h"

#ifdef HEADER_GSSAPI_GSSAPI
#include <gssapi/gssapi_krb5.h>
#endif

#define USE_KADM5_API_VERSION 2
#include <kadm5/admin.h>
#ifdef HAVE_KADM5_KADM5_ERR_H
#include <kadm5/kadm5_err.h>
#endif

static krb5_enctype des_enctypes[] = {
  ENCTYPE_DES_CBC_CRC,
  ENCTYPE_NULL
};

static krb5_enctype cur_enctypes[] = {
  ENCTYPE_DES_CBC_CRC,
  ENCTYPE_DES3_CBC_SHA1,
  ENCTYPE_NULL
};

static krb5_enctype future_enctypes[] = {
  ENCTYPE_DES_CBC_CRC,
  ENCTYPE_DES3_CBC_SHA1,
#ifdef ENCTYPE_AES128_CTS_HMAC_SHA1_96
  ENCTYPE_AES128_CTS_HMAC_SHA1_96,
#endif
#ifdef ENCTYPE_AES356_CTS_HMAC_SHA1_96
  ENCTYPE_AES256_CTS_HMAC_SHA1_96,
#endif
#ifdef ENCTYPE_ARCFOUR_HMAC
  ENCTYPE_ARCFOUR_HMAC,
#endif
  ENCTYPE_NULL
};

#ifdef THE_FUTURE_IS_NOW
#define cur_enctypes future_enctypes
#endif

static int in_admin_group(const char *username) 
{
  GROUPS *g;
  int rc, ret=0;
  
  g = groups_init();
  if (!g) {
    prtmsg("Cannot initialize groups library");
    return 0;
  }
#ifdef GROUPS_FLAG_TLS
  if (groups_config(g, GROUPS_FLAG_TLS, NULL) ||
      groups_config(g, GROUPS_FLAG_TLS_CERT, NULL) ||
      groups_config(g, GROUPS_FIELD_TLS_CADIR, "/etc/trustedcert") ||
#ifdef GROUPS_FIELD_TLS_CAFILE
      /* openldap 2.0 doesn't fully implement LDAP_OPT_X_TLS_CACERTDIR */
      /* special build of libgroups deals with this, so must we */
      groups_config(g, GROUPS_FIELD_TLS_CAFILE, "/etc/trustedcert/bundle-cmu.crt") ||
#endif
      groups_config(g, GROUPS_FLAG_NOAUTH, NULL)) {
    prtmsg("Cannot configure groups library: %s", groups_error(g));
    goto freeall;
  }
#else
  prtmsg("No SSL/TLS support in <groups.h>. authz checks will not be trustworthy");
  if (groups_config(g, GROUPS_FLAG_NOAUTH, NULL)) {
    prtmsg("Cannot configure groups library: %s", groups_error(g));
    goto freeall;
  }
#endif
  
  rc = groups_anyuser_in(g, username, REKEY_ADMIN_GROUP, "owner",
                         GROUPS_ANYUSER_ANDREW | GROUPS_ANYUSER_TRYAUTHENT |
                         GROUPS_ANYUSER_NOPTS);
  
  if (rc < 0)
    prtmsg("Unable to check group membership: %s", groups_error(g));
  else
    ret = (rc > 0);
 freeall:
  groups_destroy(g);
  return ret;
}

/* parse the client's name and determine what operations they can perform */
static void check_authz(struct rekey_session *sess) 
{
  char *realm;
#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)
  const char  *princ_realm, *c1, *c2, *c3;
#elif defined (KRB5_PRINCIPAL_MIT_STYLE)
  krb5_data *princ_realm, *c1, *c2;
  char *username;
#else
#error Cannot figure out how krb5_principals objects work
#endif
  if (krb5_get_default_realm(sess->kctx, &realm))
    return;
#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)

  princ_realm = krb5_principal_get_realm(sess->kctx, sess->princ); 
  if (!princ_realm || strncmp(princ_realm , realm, strlen(realm)))
     goto out;
  c1 = krb5_principal_get_comp_string(sess->kctx, sess->princ, 0);
  c2 = krb5_principal_get_comp_string(sess->kctx, sess->princ, 1);
  c3 = krb5_principal_get_comp_string(sess->kctx, sess->princ, 2);

  if (c1 && c2 && !c3 && !memcmp(c1, "host", 5)) {
    sess->is_host = 1;
    sess->hostname=malloc(strlen(c2)+1);
    if (sess->hostname)
      strcpy(sess->hostname, c2);
    else /* mark not a valid host, since we don't have its identification */
      sess->is_host = 0;
    goto out;
  }
  
  if (c1 && c2 && !c3 && !memcmp(c2, "admin", 5) &&
      in_admin_group(c1)) {
    sess->is_admin = 1;
  }

 out:
  krb5_xfree(realm);
#elif defined (KRB5_PRINCIPAL_MIT_STYLE)

  princ_realm = krb5_princ_realm(sess->kctx, sess->princ); 
  if (!princ_realm || strncmp(princ_realm->data , realm, strlen(realm)))
     goto out;
  if (krb5_princ_size(sess->kctx, sess->princ) != 2)
    goto out;
  c1 = krb5_princ_component(sess->kctx, sess->princ, 0);
  c2 = krb5_princ_component(sess->kctx, sess->princ, 1);

  if (c1->length == 4 && 
      !strncmp(c1->data, "host", 4)) {
    sess->is_host = 1;
    sess->hostname=malloc(c2->length+1);
    if (sess->hostname) {
      strncpy(sess->hostname, c2->data, c2->length);
      sess->hostname[c2->length]=0;
    } else /* mark not a valid host, since we don't have its identification */
      sess->is_host = 0;
    goto out;
  }
  
  if (c2->length == 5 && !strncmp(c2->data, "admin", 5)) {
    username=malloc(c1->length + 1);
    if (!username)
      goto out;
    memcpy(username, c1->data, c1->length);
    username[c1->length]=0;
    if (in_admin_group(username))
      sess->is_admin = 1;
    free(username);
  }

 out:
  krb5_free_default_realm(sess->kctx, realm);
#endif
}


/* check that the target principal is valid (in the correct realm, and
   any other checks we choose to implement (in testing, this includes
   restricting the first principal component to a specific string)) */
/*#define LIMIT_TARGET "test"*/

static int check_target(struct rekey_session *sess, krb5_principal target) 
{
  int ret=1;
  char *realm;
#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)
  const char  *princ_realm;
  const char  *c1, *c2;
#elif defined (KRB5_PRINCIPAL_MIT_STYLE)
  krb5_data *princ_realm;
  krb5_data *c1, *c2;
#endif

  if (krb5_get_default_realm(sess->kctx, &realm))
    return ret;
  
#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)

  princ_realm = krb5_principal_get_realm(sess->kctx, target); 
  if (!princ_realm || strncmp(princ_realm , realm, strlen(realm))) {
    send_error(sess, ERR_AUTHZ, "Requested principal is in wrong realm");
    goto out;
  }
  c1 = krb5_principal_get_comp_string(sess->kctx, target, 0);
  c2 = krb5_principal_get_comp_string(sess->kctx, target, 1);
#ifdef LIMIT_TARGET
  if (!c1 || strlen(c1) != strlen(LIMIT_TARGET) || strcmp(c1, LIMIT_TARGET)) {
    send_error(sess, ERR_AUTHZ, "Requested principal may not be modified");
    goto out;
  }
#else
  /* default principal exclusions: kadmin / *, local tgt. */
  if (!c1) {
badprinc:
    send_error(sess, ERR_AUTHZ, "Requested principal may not be modified");
    goto out;
  }
  if (strlen(c1) == strlen("kadmin") && !strcmp(c1, "kadmin"))
     goto badprinc;
  if (strlen(c1) == strlen("krbtgt") && !strcmp(c1, "krbtgt") &&
      strlen(c2) == strlen(princ_realm) && !strcmp(c2, princ_realm))
     goto badprinc;
#endif
  ret=0;
  
 out:
  krb5_xfree(realm);
#elif defined(KRB5_PRINCIPAL_MIT_STYLE)

  princ_realm = krb5_princ_realm(sess->kctx, target); 
  if (!princ_realm || strncmp(princ_realm->data , realm, strlen(realm))) {
    send_error(sess, ERR_AUTHZ, "Requested principal is in wrong realm");
    goto out;
  }
  if (krb5_princ_size(sess->kctx, target) < 1)
    goto out;
  c1 = krb5_princ_component(sess->kctx, target, 0);
  if (krb5_princ_size(sess->kctx, target) >= 2)
    c2 = krb5_princ_component(sess->kctx, target, 1);
  else
    c2 = NULL;
#ifdef LIMIT_TARGET
  if (!c1 || 
      c1->length != strlen(LIMIT_TARGET) || 
      strncmp(c1->data, LIMIT_TARGET, c1->length)) {
    send_error(sess, ERR_AUTHZ, "Requested principal may not be modified");
    goto out;
  }
#else
  if (!c1) { 
badprinc:
    send_error(sess, ERR_AUTHZ, "Requested principal may not be modified");
    goto out;
  }
  if (c1->length == strlen("kadmin") &&
      !strncmp(c1->data, "kadmin", c1->length))
    goto badprinc;
  if (c1->length == strlen("krbtgt") &&
      !strncmp(c1->data, "krbtgt", c1->length) &&
      c2 && c2->length == princ_realm->length &&
      !strncmp(c2->data, princ_realm->data, c2->length))
    goto badprinc;
#endif
  ret=0;
 out:
  krb5_free_default_realm(sess->kctx, realm);
#endif
  return ret;
}

/* lookup a principal in the local database, and return its id and kvno if
   requested */
static int find_principal(struct rekey_session *sess, char *principal, sqlite_int64 *princid, int *kvno) 
{
  sqlite3_stmt *getprinc=NULL;  
  int rc, match;
  
  rc = sqlite3_prepare_v2(sess->dbh, 
                          "SELECT id, kvno FROM principals WHERE name=?",
                          -1, &getprinc, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(getprinc, 1, principal, strlen(principal), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;
  match=0;
  while (SQLITE_ROW == sqlite3_step(getprinc)) {
    if (princid)
      *princid = sqlite3_column_int64(getprinc, 0);
    if (kvno)
      *kvno = sqlite3_column_int(getprinc, 1);
    if (princid && *princid == 0)
      goto dberr;
    match++;
  }
  
  rc = sqlite3_finalize(getprinc);
  getprinc=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  goto freeall;
  
 dberr:
  match = -1;
 freeall:
  if (getprinc)
    sqlite3_finalize(getprinc);  
  return match;
}

/* create a principal in the local database.
   gets the new kvno by looking up the old one in the kdb and incrementing it.
   Optionally creates the kdb entry if it does not exist */
static sqlite_int64 setup_principal(struct rekey_session *sess, char *principal, 
                                    krb5_principal target, int create, int *kvnop) 
{
  int rc;
  struct sqlite3_stmt *ins;
  int kvno, match;
  void *kadm_handle=NULL;
  kadm5_config_params kadm_param;
  char *realm=NULL;
  kadm5_principal_ent_rec ke;
  sqlite_int64 princid=0;

  match = find_principal(sess, principal, NULL, NULL);
  if (match < 0)
    goto dberr;

  if (match) {
    send_error(sess, ERR_OTHER, "Rekey for this principal already in progress");
    goto freeall;
  }

  rc=krb5_get_default_realm(sess->kctx, &realm);
  if (rc) {
    prtmsg("Unable to get default realm: %s", krb5_get_err_text(sess->kctx, rc));
    goto interr;
  }

  kadm_param.mask = KADM5_CONFIG_REALM;
  kadm_param.realm = realm;
  memset(&ke, 0, sizeof(ke));
#ifdef HAVE_KADM5_INIT_WITH_SKEY_CTX
  rc = kadm5_init_with_skey_ctx(sess->kctx, 
			    "rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, &kadm_handle);
#else
  rc = kadm5_init_with_skey("rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, NULL, &kadm_handle);
#endif
  if (rc) {
    prtmsg("Unable to initialize kadm5 library: %s", krb5_get_err_text(sess->kctx, rc));
    goto interr;
  }

  rc = kadm5_get_principal(kadm_handle, target, &ke, KADM5_KVNO);
  if (rc) {
    if (rc == KADM5_UNK_PRINC) {
      if (create) {
      } else {
        prtmsg("Principal %s does not exist", principal);
        send_error(sess, ERR_NOTFOUND, "Requested principal does not exist");
        goto freeall;
      }
    } else {
      prtmsg("Unable to initialize kadm5 library: %s", krb5_get_err_text(sess->kctx, rc));
      goto interr;
    }
    
  }
  kvno = ke.kvno + 1;

  rc = sqlite3_prepare_v2(sess->dbh, 
			  "INSERT INTO principals (name, kvno) VALUES (?, ?);",
			  -1, &ins, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(ins, 1, principal, strlen(principal), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_int(ins, 2, kvno);
  if (rc != SQLITE_OK)
    goto dberr;
  sqlite3_step(ins);    
  rc = sqlite3_finalize(ins);
  ins=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  princid  = sqlite3_last_insert_rowid(sess->dbh);
  if (kvnop)
    *kvnop=kvno;
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
 freeall:
  if (ins)
    sqlite3_finalize(ins);
  if (kadm_handle) {
    kadm5_free_principal_ent(kadm_handle, &ke);
    kadm5_destroy(kadm_handle);
  }
  if (realm) {
#if defined(HAVE_KRB5_REALM)
    krb5_xfree(realm);
#else
    krb5_free_default_realm(sess->kctx, realm);
#endif
  }

  return princid;
}

/* generates a keyset and places it in the local database */
static int generate_keys(struct rekey_session *sess, sqlite_int64 princid, int desonly) 
{
  krb5_enctype *pEtype;
  krb5_keyblock keyblock;
  krb5_error_code kc;
  sqlite3_stmt *ins=NULL;
  int rc;

  if (desonly)
    pEtype=des_enctypes;
  else
    pEtype=cur_enctypes;
  rc = sqlite3_prepare_v2(sess->dbh, 
			  "INSERT INTO keys (principal, enctype, key) VALUES (?, ?, ?);",
			  -1, &ins, NULL);
  for (;*pEtype != ENCTYPE_NULL; pEtype++) {
    kc = krb5_generate_random_keyblock(sess->kctx, *pEtype, &keyblock);
    if (kc) {
      prtmsg("Cannot generate key for enctype %d (kerberos error %s)", 
             *pEtype, krb5_get_err_text(sess->kctx, kc));
      goto interr;
    }
    rc = sqlite3_bind_blob(ins, 3, Z_keydata(&keyblock), 
                           Z_keylen(&keyblock), SQLITE_TRANSIENT);
    krb5_free_keyblock_contents(sess->kctx, &keyblock);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_int64(ins, 1, princid);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_int(ins, 2, *pEtype);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(ins);    
    rc = sqlite3_reset(ins);
    if (rc != SQLITE_OK)
      goto dberr;
  }
  rc = sqlite3_finalize(ins);
  ins=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  return 0;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
 freeall:
  return 1;
}

/* Adds a keyset to a partially initialized KEYS response */
static int add_keys_one(struct rekey_session *sess, sqlite_int64 principal, int kvno, mb_t buf, size_t *startlen) 
{
  int rc;
  sqlite3_stmt *st;
  int enctype, n;
  size_t l, curlen, last;
  const unsigned char *key;

  curlen = *startlen;
  last = curlen; /* key count goes here */
  curlen += 4; /* key count */
  rc = sqlite3_prepare(sess->dbh,"SELECT enctype, key from keys where principal=?",
		       -1, &st, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  
    rc = sqlite3_bind_int64(st, 1, principal);
    if (rc != SQLITE_OK)
      goto dberr;
    n=0;
    while (SQLITE_ROW == sqlite3_step(st)) {
      enctype = sqlite3_column_int(st, 0);
      key = sqlite3_column_blob(st, 1);
      l = sqlite3_column_bytes(st, 1);
      if (key == NULL || l == 0)
	goto interr;
      if (enctype == 0)
	goto dberr;
      if (buf_setlength(buf, curlen + 8 + l)) /* enctype, key length */
	goto memerr;
      set_cursor(buf, curlen);
      if (buf_putint(buf, enctype) || buf_putint(buf, l) ||
	  buf_putdata(buf, key, l))
	goto interr;
      curlen = curlen + 8 + l;
      if (enctype == ENCTYPE_DES_CBC_CRC) {
        if (buf_setlength(buf, curlen + 2 *(8 + l))) /* 8 is enctype, key length */
          goto memerr;
        set_cursor(buf, curlen);
        if (buf_putint(buf, ENCTYPE_DES_CBC_MD4) || buf_putint(buf, l) ||
            buf_putdata(buf, key, l))
          goto interr;
        if (buf_putint(buf, ENCTYPE_DES_CBC_MD5) || buf_putint(buf, l) ||
            buf_putdata(buf, key, l))
          goto interr;
	curlen = curlen + 2 * (8 + l);
	n += 2;
      }
      n++;
    }
    set_cursor(buf, last);
    if (buf_putint(buf, n))
      goto interr;
    rc = sqlite3_finalize(st);
    if (rc != SQLITE_OK)
      goto dberr;
    if (n == 0)   
      goto interr;
    *startlen = curlen;
    return 0;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
 freeall:
  if (st)
    sqlite3_finalize(st);
  return 1;
}

/* Set up the object used by the kadmin api for storing keys. This
   differs between mit and heimdal. */
#ifdef HAVE_KADM5_CHPASS_PRINCIPAL_WITH_KEY
static int prepare_kadm_key(krb5_key_data *k, int kvno, int enctype, int keylen,
		   const unsigned char *keydata) {
  k->key_data_ver = 1;
  k->key_data_kvno = kvno;
  k->key_data_type[0]=enctype;
  k->key_data_length[0]=keylen;
  k->key_data_contents[0]=malloc(keylen);
  if (k->key_data_contents[0] == NULL)
    return 1;
  memcpy(k->key_data_contents[0], keydata, keylen);
  return 0;
}
#else
static int prepare_kadm_key(krb5_keyblock *k, int kvno, int enctype, int keylen,
		   const unsigned char *keydata) {
  Z_enctype(k)=enctype;
  Z_keylen(k)=keylen;
  Z_keydata(k)=malloc(keylen);
  if (Z_keydata(k) == NULL)
    return 1;
  memcpy(Z_keydata(k), keydata, keylen);
  return 0;
}
#endif    

/* remove a principal and all dependent objects from the local database */
static int do_purge(struct rekey_session *sess, sqlite_int64 princid) 
{
  int rc;
  struct sqlite3_stmt *del;

  rc = sqlite3_prepare_v2(sess->dbh, 
			  "DELETE FROM keys WHERE principal = ?;",
			  -1, &del, NULL);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_int64(del, 1, princid);
    if (rc == SQLITE_OK)
      sqlite3_step(del);
    rc = sqlite3_finalize(del);
    del=0;
  }
  if (rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(sess->dbh, 
			    "DELETE FROM acl WHERE principal = ?;",
			    -1, &del, NULL);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_int64(del, 1, princid);
    if (rc == SQLITE_OK)
      sqlite3_step(del);
    rc = sqlite3_finalize(del);
    del=0;
  }
  if (rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(sess->dbh, 
			    "DELETE FROM principals WHERE id = ?;",
			    -1, &del, NULL);
  if (rc == SQLITE_OK) {
    rc = sqlite3_bind_int64(del, 1, princid);
    if (rc == SQLITE_OK)
      sqlite3_step(del);
    rc = sqlite3_finalize(del);
    del=0;
  }
  return rc;
}

/* attempt to update the kdb, given a request that has been commited
   by all its clients. If it fails, a message is stored in the database
   to help debugging */
static int do_finalize_req(struct rekey_session *sess, int no_send, 
			   char *principal, sqlite_int64 princid, 
			   krb5_principal target, int kvno) {
  sqlite3_stmt *updmsg=NULL, *selkey=NULL;
  int dbaction=0, rc, ret=1;
  unsigned int nk=0, enctype, keylen, i;
  char *realm=NULL;
  kadm5_config_params kadm_param;
  void *kadm_handle;
  kadm5_principal_ent_rec ke;
#ifdef HAVE_KADM5_CHPASS_PRINCIPAL_WITH_KEY
  krb5_key_data *k=NULL, *newk;
  int ksz = sizeof(krb5_key_data);
#else
  krb5_keyblock *k=NULL, *newk;
  int ksz = sizeof(krb5_keyblock);
#endif
  const unsigned char *keydata;
  
  rc = sqlite3_prepare_v2(sess->dbh, 
			  "UPDATE principals SET message = ? WHERE id = ?;",
			  -1, &updmsg, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_int64(updmsg, 2, princid);
  if (rc != SQLITE_OK)
    goto dberr;
  
  rc=krb5_get_default_realm(sess->kctx, &realm);
  if (rc) {
    prtmsg("Unable to get default realm: %s", krb5_get_err_text(sess->kctx, rc));
    goto interr;
  }
  kadm_param.mask = KADM5_CONFIG_REALM;
  kadm_param.realm = realm;
  memset(&ke, 0, sizeof(ke));
#ifdef HAVE_KADM5_INIT_WITH_SKEY_CTX
  rc = kadm5_init_with_skey_ctx(sess->kctx, 
			    "rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, &kadm_handle);
#else
  rc = kadm5_init_with_skey("rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, NULL, &kadm_handle);
#endif
  if (rc) {
    prtmsg("Unable to initialize kadm5 library: %s", krb5_get_err_text(sess->kctx, rc));
    goto interr;
  }

  rc = kadm5_get_principal(kadm_handle, target, &ke, KADM5_KVNO);
  if (rc) {
    if (rc == KADM5_UNK_PRINC) {
      prtmsg("Principal %s disappeared from kdc", principal);
      rc = sqlite3_bind_text(updmsg, 2, "Principal disappeared from kdc", 
			     strlen("Principal disappeared from kdc"), 
			     SQLITE_STATIC);
      if (rc != SQLITE_OK) {
	sqlite3_step(updmsg); /* finalize in freeall */
      }
      if (no_send == 0)
        send_error(sess, ERR_OTHER, "Principal disappeared from kdc");
      goto freeall;
    }
    prtmsg("Unable to initialize kadm5 library: %s", krb5_get_err_text(sess->kctx, rc));
    goto interr;
  }

  if (kvno != ke.kvno + 1) {
    prtmsg("kvno of %s changed from %d to %d; not finalizing commit", principal, kvno - 1, ke.kvno);
    rc = sqlite3_bind_text(updmsg, 2, "Principal's kvno changed on kdc", 
			   strlen("Principal's kvno changed on kdc"), 
			   SQLITE_STATIC);
    if (rc != SQLITE_OK) {
      sqlite3_step(updmsg); /* finalize in freeall */
    }
    if (no_send == 0)
      send_error(sess, ERR_OTHER, "Principal's kvno changed on kdc");
    goto freeall;
  }
  
  rc = sqlite3_prepare_v2(sess->dbh,
			  "SELECT enctype, key FROM keys WHERE principal = ?;",
			  -1, &selkey, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_int64(selkey, 1, princid);
  if (rc != SQLITE_OK)
    goto dberr;
  while (SQLITE_ROW == sqlite3_step(selkey)) {
    enctype = sqlite3_column_int(selkey, 0);
    keydata = sqlite3_column_blob(selkey, 1);
    keylen = sqlite3_column_bytes(selkey, 1);
    if (keydata == NULL || keylen == 0)
      goto interr;
    if (enctype == 0)
      goto dberr;
    if (enctype == ENCTYPE_DES_CBC_CRC)
      newk = realloc(k, ksz * (nk+3));
    else
      newk = realloc(k, ksz * (nk+1));
    if (newk == NULL)
      goto memerr;
    k = newk;

    if (prepare_kadm_key(&k[nk++], kvno, enctype, keylen, keydata))
      goto memerr;
    if (enctype == ENCTYPE_DES_CBC_CRC) {
      if (prepare_kadm_key(&k[nk++], kvno, ENCTYPE_DES_CBC_MD4, keylen, keydata))
	goto memerr;
      if (prepare_kadm_key(&k[nk++], kvno, ENCTYPE_DES_CBC_MD5, keylen, keydata))
	goto memerr;
    }
  }
  rc = sqlite3_finalize(selkey);
  selkey=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  if (nk == 0) {
    prtmsg("No keys found for %s; cannot commit", principal);
    goto interr;
  }
#ifdef HAVE_KADM5_CHPASS_PRINCIPAL_WITH_KEY
  rc = kadm5_chpass_principal_with_key(kadm_handle, target, nk, k);
#else
  rc = kadm5_setkey_principal(kadm_handle, target, k, nk);
#endif
  if (rc) {
    prtmsg("finalizing %s failed to update kdc: %s", 
	   krb5_get_err_text(sess->kctx, rc));
    
    rc = sqlite3_bind_text(updmsg, 2, "updating kdc failed", 
			   strlen("updating kdc failed"), 
			   SQLITE_STATIC);
    if (rc != SQLITE_OK) {
      sqlite3_step(updmsg); /* finalize in freeall */
    }
    if (no_send == 0)
      send_error(sess, ERR_OTHER, "Updating kdc failed");
    goto freeall;
  }
  rc = sqlite3_bind_text(updmsg, 2, "kdc update succeeded", 
                         strlen("kdc update succeeded"), 
                         SQLITE_STATIC);
  if (rc != SQLITE_OK) {
    sqlite3_step(updmsg);
    sqlite3_finalize(updmsg);
    updmsg=NULL;
  }

  if (sql_begin_trans(sess))
    goto dberr;
  dbaction=-1;
  rc = do_purge(sess, princid);
  if (rc != SQLITE_OK)
    goto dberr;
  dbaction=1;
  ret=0;
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
  if (no_send == 0)
    send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  if (no_send == 0)
    send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  if (no_send == 0)
    send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 freeall:
  if (updmsg)
    sqlite3_finalize(updmsg);
  if (selkey)
    sqlite3_finalize(selkey);
  if (dbaction > 0)
    sql_commit_trans(sess);
  else if (dbaction < 0)
    sql_rollback_trans(sess);
  if (k) {
    for (i=0; i<nk; i++) {
#ifdef HAVE_KADM5_CHPASS_PRINCIPAL_WITH_KEY
      free(k[i].key_data_contents[0]);
#else
      free(Z_keydata(&k[i]));
#endif
    }
  }
  if (kadm_handle)
    kadm5_destroy(kadm_handle);
  if (realm) {
#if defined(HAVE_KRB5_REALM)
    krb5_xfree(realm);
#else
    krb5_free_default_realm(sess->kctx, realm);
#endif
  }
  return ret;
}

/* Check to see if a principal's rekey is ready to be finalized (that is, that 
   there are no clients that have not commited it) */
static int check_uncommited(struct rekey_session *sess, sqlite_int64 princid) 
{
  sqlite3_stmt *checkcomp;
  int rc, match;
  
  rc = sqlite3_prepare_v2(sess->dbh,
			  "SELECT principal FROM acl WHERE principal = ? AND completed = 0;",
			  -1, &checkcomp, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_int64(checkcomp, 1, princid);
  if (rc != SQLITE_OK)
    goto dberr;
  match=0;
  while (SQLITE_ROW == sqlite3_step(checkcomp)) {
    match++;
  }
  rc = sqlite3_finalize(checkcomp);
  checkcomp=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  goto freeall;
 dberr:
  match = -1;
 freeall:
  if (checkcomp)
    sqlite3_finalize(checkcomp);
  return match;
}

/* Process an AUTH request containing a gss context token. 
   Returns an AUTH or OK response if successful. */
static void s_auth(struct rekey_session *sess, mb_t buf) {
  OM_uint32 maj, min, tmin, rflag;
  gss_buffer_desc in, out, outname;
  unsigned int f;
  int gss_more_accept=0, gss_more_init=0;
  unsigned char *p;
  krb5_error_code rc;
  
  if (sess->authstate) {
    send_error(sess, ERR_BADOP, "Authentication already complete");
    return;
  }
  if (krb5_init_context(&sess->kctx)) {
      
      send_fatal(sess, ERR_OTHER, "Internal kerberos error on server");
      fatal("Authentication failed: krb5_init_context failed");
  }  
  reset_cursor(buf);
  if (buf_getint(buf, &f))
    goto badpkt;
  if (f & AUTHFLAG_MORE)
    gss_more_init = 1;
  if (buf_getint(buf, (unsigned int *)&in.length))
    goto badpkt;
  in.value = buf->cursor;
  memset(&out, 0, sizeof(out));
  maj = gss_accept_sec_context(&min, &sess->gctx, GSS_C_NO_CREDENTIAL,
			       &in, GSS_C_NO_CHANNEL_BINDINGS,
			       &sess->name, &sess->mech, &out, &rflag, NULL,
			       NULL);
  if (GSS_ERROR(maj)) {
    if (out.length) {
      send_gss_token(sess, RESP_AUTHERR, 0, &out);
      gss_release_buffer(&tmin, &out);
      prt_gss_error(sess->mech, maj, min);
    } else {
      send_gss_error(sess, sess->mech, maj, min);
    }
    if (sess->gctx != GSS_C_NO_CONTEXT)
      gss_delete_sec_context(&tmin, &sess->gctx, GSS_C_NO_BUFFER);
    return;
  }
  if (maj & GSS_S_CONTINUE_NEEDED) {
    gss_more_accept=1;
    if (out.length == 0) {
      send_fatal(sess, ERR_OTHER, "Internal gss error on server");
      fatal("Authentication failed: not sending a gss token but expects a reply");
    }
  }

  if (out.length && gss_more_init == 0) {
    send_fatal(sess, ERR_OTHER, "Internal gss error on server");
    fatal("Authentication failed: would send a gss token when remote does not expect one");
  }


  if (gss_more_accept == 0) {
    unsigned short oidl;
    if ((~rflag) & (GSS_C_MUTUAL_FLAG|GSS_C_INTEG_FLAG)) {
      send_fatal(sess, ERR_AUTHN, "GSSAPI mechanism does not provide data integrity services");
      fatal("GSSAPI mechanism does not provide data integrity services");
    }   
    maj = gss_export_name(&min, sess->name, &outname);
    if (GSS_ERROR(maj)) {
      prt_gss_error(sess->mech, maj, min);
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (cannot export name from GSSAPI)");
      fatal("Cannot parse authenticated name (cannot export name from GSSAPI)");
    }
    /* check for minimum length and correct token header */
    if (outname.length < 6 || memcmp(outname.value, "\x04\x01", 2)) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (it is not a valid exported name)");
      fatal("Cannot parse authenticated name (it is not a valid exported name)");
    }
    p = outname.value;
    p += 2;
    /* extract oid wrapper length */
    oidl = (p[0] << 8) + p[1];
    p+=2;
    /* check for oid length, valid oid tag, and correct oid length. 
       (this isn't really general - a sufficiently long oid would break this,
       even if valid) */
    if (outname.length < 4 + oidl || *p++ != 0x6 || *p >= 0x80 || *p++ != oidl - 2 ) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (it is not a valid exported name)");
      fatal("Cannot parse authenticated name (it is not a valid exported name)");
    }
    oidl -= 2;
    /* check for the krb5 mechanism oid */
    if (gss_mech_krb5->length != oidl || 
	memcmp(p, gss_mech_krb5->elements, oidl)) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (it is not a kerberos name)");
      fatal("Cannot parse authenticated name (it is not a kerberos name)");
    }
    /* skip oid */
    p+=oidl;
    if (buf_setlength(buf, outname.length) ||
        buf_putdata(buf, outname.value, outname.length)) {
      send_fatal(sess, ERR_OTHER, "Internal error on server");
      fatal("internal error: cannot copy name structure");
    }      
    /* skip over the header we already parsed */
    set_cursor(buf, p - (unsigned char *)outname.value);
    gss_release_buffer(&tmin, &outname);
    if (buf_getint(buf, &f)) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (unknown error)");
      fatal("Cannot parse authenticated name (buffer is too short)");
    }
    sess->plain_name=malloc(f + 1);
    if (!sess->plain_name) {
      send_fatal(sess, ERR_OTHER, "Internal error on server");
      fatal("Cannot allocate memory");
    }
    if (buf_getdata(buf, sess->plain_name, f)) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (unknown error)");
      fatal("Cannot parse authenticated name (buffer is broken [name length=%d, input buffer size=%d])", f, outname.length - (p - (unsigned char *)outname.value) - 4);
    }
    sess->plain_name[f]=0;
    if ((rc=krb5_parse_name(sess->kctx, sess->plain_name, &sess->princ))) {
      send_fatal(sess, ERR_AUTHN, "Cannot parse authenticated name (unknown error)");
      fatal("Cannot parse authenticated name (kerberos error %s)", krb5_get_err_text(sess->kctx, rc));
    }
    sess->authstate=1;
    check_authz(sess);
    prtmsg("Authenticated as %s (host? %d admin? %d)", sess->plain_name,
           sess->is_host, sess->is_admin);
  }
  if (out.length) {
    send_gss_token(sess, RESP_AUTH, gss_more_accept, &out);
    gss_release_buffer(&tmin, &out);
  } else {
    sess_send(sess, RESP_OK, NULL);
  }
  return;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was too short for opcode");
  return;
}

/* process an AUTHERR request. logs gss error information from client and
   terminates channel */
static void s_autherr(struct rekey_session *sess, mb_t buf) 
{
  OM_uint32 maj, min;
  gss_buffer_desc in, out;
  unsigned int f;

  if (sess->authstate) {
    send_error(sess, ERR_BADOP, "Authentication already complete");
    return;
  }
  
  if (buf_getint(buf, &f))
    goto badpkt;
  if (buf_getint(buf, (unsigned int *)&in.length))
    goto badpkt;
  in.value = buf->cursor;
  memset(&out, 0, sizeof(out));
  maj = gss_accept_sec_context(&min, &sess->gctx, GSS_C_NO_CREDENTIAL,
			       &in, GSS_C_NO_CHANNEL_BINDINGS,
			       &sess->name, &sess->mech, &out, NULL, NULL,
			       NULL);
  if (GSS_ERROR(maj)) {
    prt_gss_error(sess->mech, maj, min);
  } else {
    prtmsg("got autherr packet from client, but no GSSAPI error inside");
  }
  if (out.length)
    gss_release_buffer(&min, &out);
  if (sess->gctx)
    gss_delete_sec_context(&min, &sess->gctx, GSS_C_NO_BUFFER);
  
  sess_send(sess, RESP_OK, NULL);
  sess_finalize(sess);
  exit(1);
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was too short for opcode");
  return;
}

/* process and AUTHCHAN request containing authenticated channel bindings.
   produces an AUTHCHAN response if successful */
static void s_authchan(struct rekey_session *sess, mb_t buf) 
{
  OM_uint32 maj, min, qop;
  gss_buffer_desc in, out;
  size_t flen;
  unsigned char *p;

  if (sess->authstate == 0) {
    send_error(sess, ERR_AUTHZ, "Operation not allowed on unauthenticated connection");
    return;
  }
  if (sess->authstate == 2) {
    send_error(sess, ERR_BADOP, "Authentication already complete");
    return;
  }

 flen = SSL_get_finished(sess->ssl, NULL, 0);
 if (flen == 0) {
   send_fatal(sess, ERR_AUTHN, "ssl finished message not available");
   fatal("Cannot authenticate: ssl finished message not available");
 }    
 in.length = 2 * flen;
 in.value = malloc(in.length);
 if (in.value == NULL) {
   send_fatal(sess, ERR_AUTHN, "Internal error; out of memory");
   fatal("Cannot authenticate: memory allocation failed: %s",
         strerror(errno));
 }
 p=in.value;
 if (flen != SSL_get_peer_finished(sess->ssl, p, flen)) {
   send_fatal(sess, ERR_AUTHN, "ssl finished message not available");
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_finished(sess->ssl, p, flen)) {
   send_fatal(sess, ERR_AUTHN, "ssl finished message not available");
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }

 out.length = buf->length;
 out.value = buf->value;
 
 maj = gss_verify_mic(&min, sess->gctx, &in, &out, &qop);
 if (maj == GSS_S_BAD_SIG) {
   send_fatal(sess, ERR_AUTHN, "Channel binding verification failed");
   fatal("channel binding verification failed (signature does not match)");
 }
 if (GSS_ERROR(maj)) {
   send_gss_error(sess, sess->mech, maj, min);
   free(in.value);
   return;
 }
 
 p=in.value;
 if (flen != SSL_get_finished(sess->ssl, p, flen)) {
   send_fatal(sess, ERR_AUTHN, "ssl finished message not available");
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }    
 p+=flen;
 if (flen != SSL_get_peer_finished(sess->ssl, p, flen)) {
   send_fatal(sess, ERR_AUTHN, "ssl finished message not available");
   fatal("Cannot authenticate: ssl finished message not available or size changed(!)");
 }
 memset(&out, 0, sizeof(out));
 maj = gss_get_mic(&min, sess->gctx, GSS_C_QOP_DEFAULT, &in, &out);
 free(in.value);
 if (GSS_ERROR(maj)) {
   send_gss_error(sess, sess->mech, maj, min);
   exit(1);
 }
 if (buf_setlength(buf, out.length) ||
     buf_putdata(buf, out.value, out.length)) {
    send_fatal(sess, ERR_OTHER, "Internal error on server");
    fatal("internal error: cannot pack channel binding structure");
 }
 
 sess_send(sess, RESP_AUTHCHAN, buf);
 gss_release_buffer(&min, &out);
 sess->authstate = 2;
#if 0
 {
   SSL_SESSION *ssls = SSL_get_session(sess->ssl);
   char sslid[2 * SSL_MAX_SSL_SESSION_ID_LENGTH + 4], *p;
   int i;
   sprintf(sslid, "0x");
   p=&sslid[2];
   for (i=0; i < ssls->session_id_length; i++) {
     sprintf(p, "%02x", ssls->session_id[i]);
     p+=2;
   }
   prtmsg("Authentication bound to SSL %s", sslid);
 }
#else
 prtmsg("Channel bindings sucessfully verified");
#endif
}

/* process a NEWREQ request. Creates a new request and generates keys for it.
   replies with OK if successful */
static void s_newreq(struct rekey_session *sess, mb_t buf) 
{
  char *principal=NULL, *unp;
  char **hostnames=NULL;
  int desonly;
  unsigned int l, n, flag;
  int i, rc;
  sqlite3_stmt *ins=NULL;
  int dbaction=0;
  sqlite_int64 princid;
  krb5_principal target=NULL;
  
  if (sess->is_admin == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized (you must be an administrator)");
    return;
  }
  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;
  rc = krb5_parse_name(sess->kctx, principal, &target);
  if (rc) {
    prtmsg("Cannot parse target name %s (kerberos error %s)", principal, krb5_get_err_text(sess->kctx, rc));
    send_error(sess, ERR_BADREQ, "Bad principal name");
    goto freeall;
  }

  rc=krb5_unparse_name(sess->kctx, target, &unp);
  if (rc) {
    prtmsg("Cannot get canonical name for %s: %s", principal, krb5_get_err_text(sess->kctx, rc));
    goto interr;
  } 
  if (strcmp(unp, principal)) {
    #ifdef KRB5_PRINCIPAL_HEIMDAL_STYLE
    krb5_xfree(unp);
#else
    krb5_free_unparsed_name(sess->kctx, unp);
#endif
    send_error(sess, ERR_BADREQ, "Bad principal name (it is not canonical; missing realm?)");
    goto freeall;
  }
#ifdef KRB5_PRINCIPAL_HEIMDAL_STYLE
  krb5_xfree(unp);
#else
  krb5_free_unparsed_name(sess->kctx, unp);
#endif

  if (buf_getint(buf, &flag))
    goto badpkt;
  if (flag != 0 && flag != REQFLAG_DESONLY) {
    send_error(sess, ERR_BADREQ, "Invalid flags specified");
    goto freeall;
  }
  desonly=0;
  if (flag == REQFLAG_DESONLY)
    desonly=1;
  if (buf_getint(buf, &n))
    goto badpkt;
  hostnames=calloc(n, sizeof(char *));
  if (!hostnames)
    goto memerr;
  for (i=0; i < n; i++) {
    if (buf_getint(buf, &l))
      goto badpkt;
    hostnames[i] = malloc(l + 1);
    if (!hostnames[i])
      goto memerr;
    if (buf_getdata(buf, hostnames[i], l))
      goto badpkt;
    hostnames[i][l]=0;
  }
  if (check_target(sess, target))
    goto freeall;

  if (sql_init(sess))
    goto dberrnomsg;

  if (sql_begin_trans(sess))
    goto dberrnomsg;
  dbaction=-1;
  
  princid = setup_principal(sess, principal, target, 0, NULL);
  if (princid == 0)
    goto freeall;

  rc = sqlite3_prepare_v2(sess->dbh, 
			  "INSERT INTO acl (principal, hostname) VALUES (?, ?);",
			  -1, &ins, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  for (i=0; i < n; i++) {  
    rc = sqlite3_bind_int64(ins, 1, princid);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_text(ins, 2, hostnames[i], 
                           strlen(hostnames[i]), SQLITE_STATIC);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(ins);    
    rc = sqlite3_reset(ins);
    if (rc != SQLITE_OK)
      goto dberr;
  }
  rc = sqlite3_finalize(ins);
  ins=NULL;
  if (rc != SQLITE_OK)
    goto dberr;

  if (generate_keys(sess, princid, desonly))
    goto freeall;
  
  sess_send(sess, RESP_OK, NULL);
  dbaction=1;
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:
  if (ins)
    sqlite3_finalize(ins);
  if (dbaction > 0)
    sql_commit_trans(sess);
  else if (dbaction < 0)
    sql_rollback_trans(sess);

  if (target)
    krb5_free_principal(sess->kctx, target);
  free(principal);
  if (hostnames) {
    for (i=0; i < n; i++) {
      free(hostnames[i]);
    }
    free(hostnames);
  }
}

/* Process a STATUS request. Dumps the state of a rekey request.
   returns a STATUS response if successful */ 
static void s_status(struct rekey_session *sess, mb_t buf)
{
  sqlite3_stmt *st=NULL;
  sqlite_int64 princid;
  char *principal = NULL;
  const char *hostname=NULL;
  unsigned int f, l, n;
  int rc, kvno;
  size_t curlen;

  if (sess->is_admin == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized (you must be an administrator)");
    return;
  }

  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;

  if (sql_init(sess))
    goto dberrnomsg;
  
  rc = find_principal(sess, principal, &princid, &kvno);
  if (rc < 0)
    goto dberr;
  if (rc == 0) {
    send_error(sess, ERR_NOTFOUND, "Requested principal does not have rekey in progress");
    goto freeall;
  }
  rc = sqlite3_prepare_v2(sess->dbh, 
                          "SELECT hostname,completed,attempted FROM principals,acl WHERE name=? AND principal = id",
                          -1, &st, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(st, 1, principal, strlen(principal), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;
  n=0;
  curlen=12;
  
  while (SQLITE_ROW == sqlite3_step(st)) {
    hostname = (const char *)sqlite3_column_text(st, 0);
    l = sqlite3_column_bytes(st, 0);
    if (hostname == NULL || l == 0)
      goto interr;
    if (!strcmp(hostname, "0"))
      goto dberr;
    f = 0;
    if (sqlite3_column_int(st, 1))
      f|=STATUSFLAG_COMPLETE;
    if (sqlite3_column_int(st, 2))
      f|=STATUSFLAG_ATTEMPTED;
    if (buf_setlength(buf, curlen + 4 + 4 + l))
      goto memerr;
    set_cursor(buf, curlen);
    if (buf_putint(buf, f) ||
        buf_putint(buf, l) ||
        buf_putdata(buf, hostname, l))
      goto interr;
    n++;
    curlen = curlen + 4 + 4 + l;
  }
  
  rc = sqlite3_finalize(st);
  st=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  
  reset_cursor(buf);
  buf_putint(buf, 0);
  buf_putint(buf, kvno);
  buf_putint(buf, n);
  sess_send(sess, RESP_STATUS, buf);

  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:
  if (st)
    sqlite3_finalize(st);
  free(principal);
}

/* process a GETKEYS request. Returns all the keys the host should
   add to its keytab. Produces a KEYS response if successful */
static void s_getkeys(struct rekey_session *sess, mb_t buf)
{
  int i, m, rc;
  size_t l, curlen;
  sqlite3_stmt *st, *updatt, *updcount;
  sqlite_int64 principal;
  const char *pname;
  char **names=NULL;
  unsigned int n, sl;
  int kvno, dbaction=0;
    
  if (sess->is_host == 0) {
    send_error(sess, ERR_NOKEYS, "only hosts can fetch keys with this interface");
    return;
  } 

  /* if buf->length is 0, or n is 0, then send all keys, otherwise only send 
     matching keys */
  if (buf->length > 0) {
    if (buf_getint(buf, &n))
      goto badpkt;
    if (n) {
      names=calloc(n, sizeof(char *));
      if (!names)
        goto memerr;
      for (i=0;i<n;i++) {
        if (buf_getint(buf, &sl))
          goto badpkt;
        names[i]=malloc(sl + 1);
        if (!names[i])
          goto memerr;
        if (buf_getdata(buf, names[i], sl))
          goto badpkt;
        names[i][sl]=0;
      }
    }
  }
  
  if (sql_init(sess))
    goto dberrnomsg;

  if (sql_begin_trans(sess))
    goto dberrnomsg;
  dbaction=-1;
  
  rc = sqlite3_prepare(sess->dbh,"SELECT id, name, kvno FROM principals, acl WHERE acl.hostname=? AND acl.principal=principals.id",
                       -1, &st, NULL);

  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(st, 1, sess->hostname, 
                         strlen(sess->hostname), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;

  rc = sqlite3_prepare_v2(sess->dbh, 
			  "UPDATE acl SET attempted = 1 WHERE principal = ? AND hostname = ?;",
			  -1, &updatt, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(updatt, 2, sess->hostname, 
                         strlen(sess->hostname), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;

  rc = sqlite3_prepare_v2(sess->dbh, 
			  "UPDATE principals SET downloadcount = downloadcount +1 WHERE id = ?;",
			  -1, &updcount, NULL);
  if (rc != SQLITE_OK)
    goto dberr;

  m=0;
  curlen=4;
  
  while (SQLITE_ROW == sqlite3_step(st)) {
    principal=sqlite3_column_int64(st, 0);
    pname = (const char *)sqlite3_column_text(st, 1);
    kvno = sqlite3_column_int(st, 2);
    l = sqlite3_column_bytes(st, 1);
    if (pname == NULL || l == 0)
      goto interr;
    if (!strcmp(pname, "0") || 
	principal == 0)
      goto dberr;

    if (names) {
      for (i=0;i<n;i++)
        if (!strcmp(pname, names[i]))
          break;
      /* don't send this one */
      if (i >= n)
        continue;
    }

    if (buf_setlength(buf, curlen + 8 + l)) /* name length, kvno */
      goto memerr;
    set_cursor(buf, curlen);
    if (buf_putint(buf, l) || 
	buf_putdata(buf, pname, l) ||
	buf_putint(buf, kvno))
      goto interr;
    curlen = curlen + 8 + l;
    if (add_keys_one(sess, principal, kvno, buf, &curlen))
      goto freeall;

    m++;

    rc = sqlite3_bind_int64(updatt, 1, principal);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(updatt);    
    rc = sqlite3_reset(updatt);
    if (rc != SQLITE_OK)
      goto dberr;

    rc = sqlite3_bind_int64(updcount, 1, principal);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(updcount);    
    rc = sqlite3_reset(updcount);
    if (rc != SQLITE_OK)
      goto dberr;
  }
  if (m == 0) {
    if (names)
      send_error(sess, ERR_NOKEYS, "None of the requested keys are available for this host");
    else
      send_error(sess, ERR_NOKEYS, "No keys available for this host");
  } else {
    set_cursor(buf, 0);
    if (buf_putint(buf, m))
      goto interr;
    sess_send(sess, RESP_KEYS, buf);
    dbaction=1;
  }    
  
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:
  if (st)
    sqlite3_finalize(st);
  if (updatt)
    sqlite3_finalize(updatt);
  if (updcount)
    sqlite3_finalize(updcount);
  if (dbaction > 0)
    sql_commit_trans(sess);
  else if (dbaction < 0)
    sql_rollback_trans(sess);
  if (names) {
    for (i=0;i<n;i++)
      free(names[i]);
    free(names);
  }
}

/* process a COMMITKEY request. This request (verb) that the client has
   successfully stored the key. if appropriate, we store the new keys to 
   the kdb. Replies with OK if successful. */
static void s_commitkey(struct rekey_session *sess, mb_t buf)
{
  sqlite3_stmt *getprinc=NULL, *updcomp=NULL, *updcount=NULL;
  sqlite_int64 princid;
  unsigned int l, kvno, no_send = 0;
  char *principal = NULL;
  int dbaction=0, rc, match;
  krb5_principal target=NULL;
    

  if (sess->is_host == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized");
    return;
  }
  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;
  rc = krb5_parse_name(sess->kctx, principal, &target);
  if (rc) {
    prtmsg("Cannot parse target name %s (kerberos error %s)", principal, krb5_get_err_text(sess->kctx, rc));
    send_error(sess, ERR_BADREQ, "Bad principal name");
    goto freeall;
  }

  if (buf_getint(buf, &kvno))
    goto badpkt;
  
  if (check_target(sess, target))
    goto freeall;

  if (sql_init(sess))
    goto dberrnomsg;

  rc = sqlite3_prepare_v2(sess->dbh, 
                          "SELECT id from principals where name=? and kvno = ?",
                          -1, &getprinc, NULL);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_text(getprinc, 1, principal, strlen(principal), SQLITE_STATIC);
  if (rc != SQLITE_OK)
    goto dberr;
  rc = sqlite3_bind_int(getprinc, 2, kvno);
  if (rc != SQLITE_OK)
    goto dberr;
  match=0;
  princid = -1;
  while (SQLITE_ROW == sqlite3_step(getprinc)) {
    princid = sqlite3_column_int64(getprinc, 0);
    if (princid == 0)
      goto dberr;
    match++;
  }
  rc = sqlite3_finalize(getprinc);
  getprinc=NULL;
  if (rc != SQLITE_OK)
    goto dberr;
  if (match == 0) {
    send_error(sess, ERR_AUTHZ, "No rekey for this principal is in progress");
    prtmsg("%s tried to commit %s %d, but it is not active",
	   sess->hostname, principal, kvno);
    goto freeall;
  }

  if (sess->is_host) {
    if (sql_begin_trans(sess))
      goto dberr;
    dbaction = -1;
    
    rc = sqlite3_prepare_v2(sess->dbh, 
                            "UPDATE acl SET completed = 1 WHERE principal = ? AND hostname = ?;",
                            -1, &updcomp, NULL);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_int64(updcomp, 1, princid);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_text(updcomp, 2, sess->hostname, 
                           strlen(sess->hostname), SQLITE_STATIC);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(updcomp);
    rc = sqlite3_finalize(updcomp);
    updcomp=NULL;
    if (rc != SQLITE_OK)
      goto dberr;

    rc = sqlite3_prepare_v2(sess->dbh, 
                            "UPDATE principals SET commitcount = commitcount +1 WHERE id = ?;",
                            -1, &updcount, NULL);
    if (rc != SQLITE_OK)
      goto dberr;
    rc = sqlite3_bind_int64(updcount, 1, princid);
    if (rc != SQLITE_OK)
      goto dberr;
    sqlite3_step(updcount);
    rc = sqlite3_finalize(updcount);
    updcount=NULL;
    if (rc != SQLITE_OK)
      goto dberr;
    dbaction=0;
    if (sql_commit_trans(sess))
      goto dberr;
    /* at this point, the client doesn't care about future errors */
    sess_send(sess, RESP_OK, NULL);
    no_send = 1;
  }
  
  match = check_uncommited(sess, princid);
  if (match < 0)
    goto dberr;
  /* not done yet */
  if (match)
    goto freeall;

  do_finalize_req(sess, no_send, principal, princid, target, kvno);
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  if (no_send == 0)
    send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 memerr:
  if (no_send == 0)
    send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:
  if (getprinc)
    sqlite3_finalize(getprinc);
  if (updcomp)
    sqlite3_finalize(updcomp);
  if (updcount)
    sqlite3_finalize(updcount);
  if (dbaction > 0)
    sql_commit_trans(sess);
  else if (dbaction < 0)
    sql_rollback_trans(sess);
  if (target)
    krb5_free_principal(sess->kctx, target);  
  free(principal);

}

/* Process a SIMPLEKEY request. This is a request by an admin to update the 
   key of a single principal and return a keyset for it. No acl/hostlist is 
   set up. This is used for rekeying non-shared principals and may be used 
   to create a new principal. sends a KEYS response if successful */
static void s_simplekey(struct rekey_session *sess, mb_t buf)
{
  char *principal=NULL;
  int desonly;
  unsigned int l, flag;
  int rc, kvno;
  int dbaction=0;
  sqlite_int64 princid;
  krb5_principal target=NULL;
  size_t curlen;

  if (sess->is_admin == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized (you must be an administrator)");
    return;
  }
  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;
  rc = krb5_parse_name(sess->kctx, principal, &target);
  if (rc) {
    prtmsg("Cannot parse target name %s (kerberos error %s)", principal, krb5_get_err_text(sess->kctx, rc));
    send_error(sess, ERR_BADREQ, "Bad principal name");
    goto freeall;
  }

  if (buf_getint(buf, &flag))
    goto badpkt;
  if (flag != 0 && flag != REQFLAG_DESONLY) {
    send_error(sess, ERR_BADREQ, "Invalid flags specified");
    goto freeall;
  }
  desonly=0;
  if (flag == REQFLAG_DESONLY)
    desonly=1;

  if (check_target(sess, target))
    goto freeall;

  if (sql_init(sess))
    goto dberrnomsg;

  if (sql_begin_trans(sess))
    goto dberrnomsg;
  dbaction=-1;
  
  princid = setup_principal(sess, principal, target, 0, &kvno);
  if (princid == 0)
    goto freeall;

  if (generate_keys(sess, princid, desonly))
    goto freeall;

  if (buf_setlength(buf, 12 + strlen(principal))) /* key count, 
                                                     name length, kvno */
    goto memerr;
  if (buf_putint(buf, 1) || buf_putint(buf, l) || 
      buf_putdata(buf, principal, l) || buf_putint(buf, kvno))
    goto interr;
  curlen = 12 + strlen(principal);
  if (add_keys_one(sess, princid, kvno, buf, &curlen))
    goto freeall;
  dbaction=1;
  sess_send(sess, RESP_KEYS, buf);
  
  goto freeall;
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 interr:
  send_error(sess, ERR_OTHER, "Server internal error");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:
  if (dbaction > 0)
    sql_commit_trans(sess);
  else if (dbaction < 0)
    sql_rollback_trans(sess);

  if (target)
    krb5_free_principal(sess->kctx, target);
  free(principal);
}

/* Process an ABORTREQ request. Deletes a request from the local database */
static void s_abortreq(struct rekey_session *sess, mb_t buf)
{
  char *principal = NULL;
  sqlite_int64 princid;
  int match;
  unsigned int l;
  
  if (sess->is_admin == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized (you must be an administrator)");
    return;
  }
  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;
  
  if (sql_init(sess))
    goto dberrnomsg;

  match = find_principal(sess, principal, &princid, NULL);
  if (match < 0)
    goto dberr;

  if (match == 0) {
    send_error(sess, ERR_NOTFOUND, "Requested principal does not have rekey in progress");
    goto freeall;
  }
  do_purge(sess, princid);
  sess_send(sess, RESP_OK, NULL);  
  goto freeall;
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:  
  free(principal);
}

static void s_finalize(struct rekey_session *sess, mb_t buf)
{
  char *principal = NULL;
  sqlite_int64 princid;
  unsigned int l;
  int rc, match, kvno;
  krb5_principal target=NULL;

  if (sess->is_admin == 0) {
    send_error(sess, ERR_AUTHZ, "Not authorized (you must be an administrator)");
    return;
  }

  if (buf_getint(buf, &l))
    goto badpkt;
  principal = malloc(l + 1);
  if (!principal)
    goto memerr;
  if (buf_getdata(buf, principal, l))
    goto badpkt;
  principal[l]=0;
  rc = krb5_parse_name(sess->kctx, principal, &target);
  if (rc) {
    prtmsg("Cannot parse target name %s (kerberos error %s)", principal, krb5_get_err_text(sess->kctx, rc));
    send_error(sess, ERR_BADREQ, "Bad principal name");
    goto freeall;
  }

  if (sql_init(sess))
    goto dberrnomsg;

  match = find_principal(sess, principal, &princid, &kvno);
  if (match < 0)
    goto dberr;

  if (match == 0) {
    send_error(sess, ERR_NOTFOUND, "Requested principal does not have rekey in progress");
    goto freeall;
  }

  match = check_uncommited(sess, princid);
  if (match < 0)
    goto dberr;
  
  /* not done yet */
  if (match) {
    send_error(sess, ERR_OTHER, "Request is not ready to be finalized");
    goto freeall;
  } 

  if (do_finalize_req(sess, 0, principal, princid, target, kvno))
    goto freeall;
  sess_send(sess, RESP_OK, NULL);
 dberr:
  prtmsg("database error: %s", sqlite3_errmsg(sess->dbh));
 dberrnomsg:
  send_error(sess, ERR_OTHER, "Server internal error (database failure)");
  goto freeall;
 memerr:
  send_error(sess, ERR_OTHER, "Server internal error (out of memory)");
  goto freeall;
 badpkt:
  send_error(sess, ERR_BADREQ, "Packet was corrupt or too short");
 freeall:  
  if (target)
    krb5_free_principal(sess->kctx, target);  
  free(principal);
}
static void (*func_table[])(struct rekey_session *, mb_t) = {
  NULL,
  s_auth,
  s_autherr,
  s_authchan,
  s_newreq,
  s_status,
  s_getkeys,
  s_commitkey,
  s_simplekey,
  s_abortreq,
  s_finalize
};

void run_session(int s) {
  struct rekey_session sess;
  mb_t buf;
  int opcode;

  memset(&sess, 0, sizeof(sess));
  buf = buf_alloc(1);
  if (!buf) {
    close(s);
    fatal("Cannot allocate memory: %s", strerror(errno));
  }
  sess.ssl = do_ssl_accept(s);
  child_cleanup();
  sess.initialized=1;
  sess.state = REKEY_SESSION_LISTENING;
  for (;;) {
    opcode = sess_recv(&sess, buf);
    
    if (opcode == -1) {
      sess_finalize(&sess);
      ssl_cleanup();
      fatal("Connection closed");
    }
    if (sess.authstate != 2 && opcode > 3) {
      send_error(&sess, ERR_AUTHZ, "Operation not allowed on unauthenticated connection");
      continue;
    }
    
    if (opcode <= 0 || opcode > MAX_OPCODE) {
       send_error(&sess, ERR_BADOP, "Function code was out of range");
    } else {
      func_table[opcode](&sess, buf);
      if (sess.initialized == 0)
        fatal("session terminated during operation %d, but handler did not exit", opcode);
      if (sess.state != REKEY_SESSION_IDLE) {
        send_error(&sess, ERR_OTHER, "Internal error in server");
        prtmsg("Handler for %d did not send a reply", opcode);
      }
      sess.state = REKEY_SESSION_LISTENING;
    }
  }
}
