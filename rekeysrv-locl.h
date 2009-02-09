
#ifndef _SRV_LOCL_H
#define _SRV_LOCL_H

#ifdef SESS_PRIVATE
#define NEED_KRB5
#define NEED_SSL
#define NEED_GSSAPI
#define NEED_SQLITE
#endif

#ifdef NEED_KRB5
#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif
#ifndef HAVE_KRB5_GET_ERR_TEXT
#include <com_err.h>
#define krb5_get_err_text(c, r) error_message(r)
#endif
#ifdef HAVE_KRB5_KEYBLOCK_ENCTYPE
#define Z_keydata(keyblock)     ((keyblock)->contents)
#define Z_keylen(keyblock)      ((keyblock)->length)
#define Z_enctype(keyblock)     ((keyblock)->enctype)
#else
#define Z_keydata(keyblock)     ((keyblock)->keyvalue.data)
#define Z_keylen(keyblock)      ((keyblock)->keyvalue.length)
#define Z_enctype(keyblock)     ((keyblock)->keytype)
#endif
#if defined(HAVE_KRB5_C_MAKE_RANDOM_KEY) && !defined(HAVE_KRB5_GENERATE_RANDOM_KEYBLOCK)
#define krb5_generate_random_keyblock krb5_c_make_random_key
#endif
#if defined(HAVE_KRB5_PRINCIPAL_GET_REALM) && defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING) && defined(HAVE_KRB5_REALM)
#define KRB5_PRINCIPAL_HEIMDAL_STYLE 1
#elif defined (HAVE_KRB5_PRINC_REALM) && defined(HAVE_KRB5_PRINC_COMPONENT) && !defined(HAVE_KRB5_REALM)
#define KRB5_PRINCIPAL_MIT_STYLE 1
#else
#error Cannot figure out how krb5_principal accessors work
#endif
#endif

#ifdef NEED_GSSAPI
#ifdef HEADER_GSSAPI_GSSAPI
#include <gssapi/gssapi.h>
#else
#include <gssapi.h>
#endif
#endif

#ifdef NEED_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
void ssl_fatal(SSL *, int);
SSL *do_ssl_accept(int s);
#endif

#ifdef NEED_SQLITE
#include <sqlite3.h>
#if SQLITE_VERSION_NUMBER < 3005000
#define sqlite3_prepare_v2 sqlite3_prepare
#endif
#endif

#ifdef SESS_PRIVATE
struct rekey_session {
  int initialized;
  int state;
  SSL *ssl;
  krb5_context kctx;
  gss_ctx_id_t gctx;
  gss_OID mech;
  gss_name_t name;
  char *plain_name;
  char *hostname;
  krb5_principal princ;
  int authstate;
  int is_admin;
  int is_host;
  sqlite3 *dbh;
};
#define REKEY_SESSION_LISTENING 0
#define REKEY_SESSION_SENDING 1
#define REKEY_SESSION_IDLE 2
#else
struct rekey_session;
#endif

struct gss_OID_desc_struct;
struct gss_buffer_desc_struct;
struct sockaddr;
struct mem_buffer;

void child_cleanup(void) ;
void ssl_startup(void);
void ssl_cleanup(void);
void net_startup(void);
void run_session(int);
void sess_finalize(struct rekey_session *);
void sess_send(struct rekey_session *, int, struct mem_buffer *);
int sess_recv(struct rekey_session *, struct mem_buffer *);
void send_error(struct rekey_session *, int errcode, char *msg);
void send_fatal(struct rekey_session *, int errcode, char *msg);
void send_gss_error(struct rekey_session *, struct gss_OID_desc_struct *,
    int, int);
void send_gss_token(struct rekey_session *, int, int, struct gss_buffer_desc_struct *);
int run_accept_loop(void (*)(int , struct sockaddr *));
int sql_init(struct rekey_session *);
int sql_begin_trans(struct rekey_session *);
int sql_commit_trans(struct rekey_session *);
int sql_rollback_trans(struct rekey_session *);

void fatal(const char *, ...);
void prtmsg(const char *, ...);
void vprtmsg(const char *msg, va_list ap);

#endif
