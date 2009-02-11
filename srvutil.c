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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <netdb.h>
#include <arpa/inet.h>

#define DBFILE "/tmp/rekey.db"

#define SESS_PRIVATE
#define NEED_SSL
#define NEED_KRB5
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

  msgbuf = buf_alloc(9+strlen(msg));
  if (!msgbuf)
    return;
  buf_setlength(msgbuf, 9+strlen(msg));
  if (buf_putint(msgbuf, errcode) ||
      buf_putint(msgbuf, strlen(msg)) ||
      buf_putdata(msgbuf, msg, strlen(msg)+1))
    return;
  sess_send(sess, RESP_ERR, msgbuf);
  buf_free(msgbuf);
}

void send_fatal(struct rekey_session *sess, int errcode, char *msg) 
{
  mb_t msgbuf;

  msgbuf = buf_alloc(9+strlen(msg));
  if (!msgbuf)
    return;
  buf_setlength(msgbuf,9+strlen(msg));
  if (buf_putint(msgbuf, errcode) ||
      buf_putint(msgbuf, strlen(msg)) ||
      buf_putdata(msgbuf, msg, strlen(msg)+1))
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
  buf_setlength(auth, tok->length + 8);
    
  f=0;
  if (gss_more_accept) f|=AUTHFLAG_MORE;
  if (buf_putint(auth, f) ||
      buf_putint(auth, tok->length) ||
      buf_putdata(auth, tok->value, tok->length)) {
    send_fatal(sess, ERR_OTHER, "Internal error on server");
    fatal("internal error: cannot pack authentication structure");
  }
    
  sess_send(sess, RESP_AUTH, auth);
  buf_free(auth);
}

#include "sqlinit.h"
int sql_init(struct rekey_session *sess) 
{
  sqlite3 *dbh;
  int rc, i;
  char *sql, *errmsg;

  if (sess->dbh)
    return 0;
  
#if SQLITE_VERSION_NUMBER >= 3005000
  rc = sqlite3_open_v2(DBFILE, &dbh, SQLITE_OPEN_READWRITE, NULL);
  if (rc == SQLITE_OK) {
    sess->dbh = dbh;
    return 0;
  }
  
  if (rc != SQLITE_ERROR && rc != SQLITE_CANTOPEN) {
    prtmsg("Cannot open database: %d", rc);
    return 1;
  }

  rc = sqlite3_open_v2(DBFILE, &dbh, SQLITE_OPEN_READWRITE | 
                       SQLITE_OPEN_CREATE, NULL);
  if (rc != SQLITE_OK) { 
    prtmsg("Cannot create/open database: %d", rc);
    return 1;
  }
#else
  rc = sqlite3_open(DBFILE, &dbh);
  if (rc != SQLITE_OK) { 
    prtmsg("Cannot create/open database: %d", rc);
    return 1;
  }
#endif
    
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
      return 1;
    }
  }
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
