/*
 * Copyright (c) 2008-2009, 2013, 2015 Carnegie Mellon University.
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <netdb.h>
#include <arpa/inet.h>

#define SESS_PRIVATE
#define NEED_SSL
#define NEED_KRB5
#define NEED_KADM5
#define NEED_SQLITE
#include "rekeysrv-locl.h"
#include "rekey-locl.h"
#include "protocol.h"
#include "memmgt.h"

#include <openssl/err.h>

void vprtmsg(const char *msg, va_list ap) {
  /* vsyslog is not standard, but can't invoke vsnprintf multiple times */
  /* gnulib has vasprintf */
#if 1
  char *m=NULL;
  vasprintf(&m, msg, ap);
  if (m) {
     syslog(LOG_ERR, "%s", m);
     free(m);
  } else {
     syslog(LOG_ERR, "Cannot format message; malloc failed");
  }
#else
  vsyslog(LOG_ERR, msg, ap);
#endif
}

void sess_finalize(struct rekey_session *sess) 
{
  OM_uint32 min;
  if (sess->state == REKEY_SESSION_SENDING)
    prtmsg("warning: session closed before reply sent");
  if (sess->ssl) {
    SSL_shutdown(sess->ssl);
    SSL_free(sess->ssl);
  }
  if (sess->kadm_handle)
    kadm5_destroy(sess->kadm_handle);
  if (sess->realm) {
#if defined(HAVE_KRB5_REALM)
    krb5_xfree(sess->realm);
#else
    krb5_free_default_realm(sess->kctx, sess->realm);
#endif
  }
  if (sess->princ)
    krb5_free_principal(sess->kctx, sess->princ);
  if (sess->kctx)
    krb5_free_context(sess->kctx);
  if (sess->gctx)
    (void)gss_delete_sec_context(&min, &sess->gctx, GSS_C_NO_BUFFER);
  if (sess->name)
    (void)gss_release_name(&min, &sess->name);
  if (sess->dbh)
    sqlite3_close(sess->dbh);
  free(sess->hostname);
  free(sess->plain_name);
  memset(&sess, 0, sizeof(sess));
}

void sess_send(struct rekey_session *sess, int opcode, mb_t buf) 
{
  if (sess->state != REKEY_SESSION_SENDING) {
    prtmsg("Cannot send message (of type %d) while in state %d\n", opcode,
           sess->state);
    return;
  }
  do_send(sess->ssl, opcode, buf);
  sess->state = REKEY_SESSION_IDLE;
}


int sess_recv(struct rekey_session *sess, mb_t buf) 
{
  int ret;
  if (sess->state != REKEY_SESSION_LISTENING) {
    prtmsg("Cannot read from session while in state %d\n",
           sess->state);
    return -1;
  }
  ret = do_recv(sess->ssl, buf);
  if (ret > 0)
    sess->state = REKEY_SESSION_SENDING;
  return ret;
}


void send_error(struct rekey_session *sess, int errcode, char *msg) 
{
  mb_t msgbuf;
  char *eom = "";

  msgbuf = buf_alloc(9+strlen(msg));
  if (!msgbuf)
    return;
  if (buf_appendint(msgbuf, errcode) ||
      buf_appendstring(msgbuf, msg) ||
      buf_appenddata(msgbuf, eom, 1))
    return;
  sess_send(sess, RESP_ERR, msgbuf);
  buf_free(msgbuf);
}

void send_fatal(struct rekey_session *sess, int errcode, char *msg) 
{
  mb_t msgbuf;
  char *eom = "";

  msgbuf = buf_alloc(9+strlen(msg));
  if (!msgbuf)
    return;
  if (buf_appendint(msgbuf, errcode) ||
      buf_appendstring(msgbuf, msg) ||
      buf_appenddata(msgbuf, eom, 1))
    return;
  sess_send(sess, RESP_FATAL, msgbuf);
  buf_free(msgbuf);
  sess_finalize(sess);
}

static void send_gss_error_cb(void *rock, gss_buffer_t status_string) 
{
  mb_t outbuf = (mb_t)rock;
  int newsize = outbuf->length + status_string->length + 1;
  char *p;

  prtmsg("%.*s",
         (int)status_string->length,
         (char *)status_string->value);
  if (buf_grow(outbuf, newsize))
    return;

  p = ((char *)outbuf->value) + outbuf->length;
  memcpy(p, status_string->value, status_string->length);
  p += status_string->length;
  *p++=0;
  if (p != ((char *)outbuf->value) + newsize)
    prtmsg("Warning: send_gss_error_cb: pointer mismatch: %p + %d != %p",
           outbuf->value, newsize, p);
  outbuf->length = newsize; 
}

void send_gss_error(struct rekey_session *sess, gss_OID mech, int errmaj, int errmin) 
{
  mb_t msgbuf;
  msgbuf=buf_alloc(8);
  if (!msgbuf)
    return;
  buf_setlength(msgbuf, 8);
  do_gss_error(mech, errmaj, errmin, send_gss_error_cb, msgbuf);
  reset_cursor(msgbuf);
  if (buf_putint(msgbuf, ERR_AUTHN) ||
      buf_putint(msgbuf, msgbuf->length - 8)) {
    prtmsg("internal error in send_gss_error, cannot pack message");
    buf_free(msgbuf);
    return;
  }
  sess_send(sess, RESP_ERR, msgbuf);
  buf_free(msgbuf);
}

void send_gss_token(struct rekey_session *sess, int opcode,
			   int gss_more_accept, gss_buffer_t tok) {
  mb_t auth;
  int f;

  auth=buf_alloc(tok->length+8);
  if (auth == NULL) {
    send_fatal(sess, ERR_OTHER, "Cannot allocate memory on server");
    fatal("Cannot authenticate: memory allocation failed: %s",
	  strerror(errno));
  }
    
  f=0;
  if (gss_more_accept) f|=AUTHFLAG_MORE;
  if (buf_appendint(auth, f) ||
      buf_appendint(auth, tok->length) ||
      buf_appenddata(auth, tok->value, tok->length)) {
    send_fatal(sess, ERR_OTHER, "Internal error on server");
    fatal("internal error: cannot pack authentication structure");
  }
    
  sess_send(sess, RESP_AUTH, auth);
  buf_free(auth);
}


#if defined(KRB5_PRINCIPAL_HEIMDAL_STYLE)

int princ_ncomp_eq(krb5_context context, krb5_principal princ, int val)
{
  const char *s;
  if (val <=0)
    return 0;
  if (!(s=krb5_principal_get_comp_string(context, princ, val-1)) ||
      (strlen(s) == 0))
    return 0;
  if ((s=krb5_principal_get_comp_string(context, princ, val)) &&
      (strlen(s) > 0))
    return 0;
  return 1;
}

#elif defined (KRB5_PRINCIPAL_MIT_STYLE)

int compare_princ_comp(krb5_context context, krb5_principal princ, int n,
                       char *ts)
{
  krb5_data *obj = krb5_princ_component(context, princ, n);
  if (obj == NULL)
     return 0;
  return obj->length == strlen(ts) && !strncmp(obj->data, ts, obj->length);
}

char *dup_comp_string(krb5_context context, krb5_principal princ, int n)
{
  krb5_data *obj = krb5_princ_component(context, princ, n);
  char *ret;
  if (obj == NULL)
     return NULL;
  ret=malloc(obj->length+1);
  memcpy(ret, obj->data, obj->length);
  ret[obj->length]=0;
  return ret;
}

#endif

int krealm_init(struct rekey_session *sess) {
  int rc;
  char *realm=NULL;  
  if (sess->realm) {
    return 0;
  }
  rc=krb5_get_default_realm(sess->kctx, &realm);
  if (rc) {
    prtmsg("Unable to get default realm: %s", krb5_get_err_text(sess->kctx, rc));
    return rc;
  }
  sess->realm = realm;
  return 0;
}

int kadm_init(struct rekey_session *sess) 
{
  void *kadm_handle=NULL;
  kadm5_config_params kadm_param;
  int rc;

  rc = krealm_init(sess);
  if (rc)
    return rc;

  kadm_param.mask = KADM5_CONFIG_REALM;
  kadm_param.realm = sess->realm;

#ifdef HAVE_KADM5_INIT_WITH_SKEY_CTX
  rc = kadm5_init_with_skey_ctx(sess->kctx, "rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, &kadm_handle);
#else
  rc = kadm5_init_with_skey(sess->kctx, "rekey/admin", NULL, KADM5_ADMIN_SERVICE,
			    &kadm_param, KADM5_STRUCT_VERSION, 
			    KADM5_API_VERSION_2, NULL, &kadm_handle);
#endif
  if (rc) {
    prtmsg("Unable to initialize kadm5 library: %s", krb5_get_err_text(sess->kctx, rc));
    return rc;
  }
   sess->kadm_handle = kadm_handle;
  return 0;
}

#include "sqlinit.h"
int sql_init(struct rekey_session *sess) 
{
  sqlite3 *dbh;
  int dblock, rc, i;
  char *sql, *errmsg;

  if (sess->dbh)
    return 0;
  
  dblock = open(REKEY_DATABASE_LOCK, O_WRONLY | O_CREAT, 0644);
  if (dblock < 0) {
    prtmsg("Cannot create/open database lock: %s", strerror(errno));
    return 1;
  }

  if (flock(dblock, LOCK_EX)) {
    prtmsg("Cannot obtain database lock: %s", strerror(errno));
    close(dblock);
    return 1;
  }

#if SQLITE_VERSION_NUMBER >= 3005000
  rc = sqlite3_open_v2(REKEY_LOCAL_DATABASE, &dbh, SQLITE_OPEN_READWRITE, NULL);
  if (rc == SQLITE_OK) {
    sess->db_lock = dblock;
    sess->dbh = dbh;
    return 0;
  }
  
  if (rc != SQLITE_ERROR && rc != SQLITE_CANTOPEN) {
    prtmsg("Cannot open database: %d", rc);
    close(dblock);
    return 1;
  }

  rc = sqlite3_open_v2(REKEY_LOCAL_DATABASE, &dbh, SQLITE_OPEN_READWRITE | 
                       SQLITE_OPEN_CREATE, NULL);
  if (rc != SQLITE_OK) { 
    prtmsg("Cannot create/open database: %d", rc);
    close(dblock);
    return 1;
  }
#else
  rc = sqlite3_open(REKEY_LOCAL_DATABASE, &dbh);
  if (rc != SQLITE_OK) { 
    prtmsg("Cannot create/open database: %d", rc);
    close(dblock);
    return 1;
  }
#endif

  rc = sqlite3_busy_timeout(dbh, 30000);
  if (rc != SQLITE_OK) {
    prtmsg("Failed setting database busy handler: %d", rc);
    sqlite3_close(dbh);
    close(dblock);
    return 1;
  }
    
#if SQLITE_VERSION_NUMBER >= 3003007 /* need support for CREATE TRIGGER IF NOT EXIST */
  for (sql=sql_embeded_init[i=0]; sql;sql=sql_embeded_init[++i]) {
    rc = sqlite3_exec(dbh, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
      if (errmsg) {
        prtmsg("SQL Initialization action %d failed: %s", i, errmsg);
        sqlite3_free(errmsg);
      } else {
        prtmsg("SQL Initialization action %d failed: %d", i, rc);
      }
      sqlite3_close(dbh);
      close(dblock);
      return 1;
    }
  }
#else
#warning Automatic database initialization not available
#endif
  sess->db_lock = dblock;
  sess->dbh = dbh;
  return 0;
}

int sql_begin_trans(struct rekey_session *sess) 
{
  char *errmsg;
  int rc;
  
  rc = sqlite3_exec(sess->dbh, "BEGIN TRANSACTION", NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    if (errmsg) {
      prtmsg("SQL BEGIN TRANSACTION failed: %s", errmsg);
      sqlite3_free(errmsg);
    } else {
      prtmsg("SQL BEGIN TRANSACTION failed: %d", rc);
    }
    return 1;
  }
  return 0;
}

int sql_commit_trans(struct rekey_session *sess) 
{
  char *errmsg;
  int rc;
  
  rc = sqlite3_exec(sess->dbh, "COMMIT TRANSACTION", NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    if (errmsg) {
      prtmsg("SQL COMMIT TRANSACTION failed: %s", errmsg);
      sqlite3_free(errmsg);
    } else {
      prtmsg("SQL COMMIT TRANSACTION failed: %d", rc);
    }
    return 1;
  }
  return 0;
}

int sql_rollback_trans(struct rekey_session *sess) 
{
  char *errmsg;
  int rc;
  
  rc = sqlite3_exec(sess->dbh, "ROLLBACK TRANSACTION", NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    if (errmsg) {
      prtmsg("SQL ROLLBACK TRANSACTION failed: %s", errmsg);
      sqlite3_free(errmsg);
    } else {
      prtmsg("SQL ROLLBACK TRANSACTION failed: %d", rc);
    }
    return 1;
  }
  return 0;
}
