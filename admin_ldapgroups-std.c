#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <alloca.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <sasl/sasl.h>
#include <openssl/ssl.h>
#include <ctype.h>

#define SESS_PRIVATE
#define NEED_KRB5
#include "rekeysrv-locl.h"
#define NO_FILTER "(objectClass=*)"
#define USER_INGROUP_FILTER "(&(uid=%s)(isMemberOf=%s))"
#define LDAP_BINDDN ""
#define LDAP_PWFILE ""

static char *rekey_admin_group;

#define LDAP_SET_OPTION(ld,option,invalue) \
  rc=ldap_set_option(ld,option,invalue); \
  if (rc!=LDAP_SUCCESS) \
  { \
    if (rc == LDAP_OPT_ERROR) \
      prtmsg("ldap_set_option(" #option ") failed");	\
    else \
      prtmsg("ldap_set_option(" #option ") failed: %s",ldap_err2string(rc)); \
    goto freeall; \
  }

#define LDAP_GET_OPTION(ld,option,outvalue) \
  rc=ldap_get_option(ld,option,outvalue); \
  if (rc!=LDAP_SUCCESS) \
  { \
    if (rc == LDAP_OPT_ERROR) \
      prtmsg("ldap_get_option(" #option ") failed");	\
    else \
      prtmsg("ldap_get_option(" #option ") failed: %s",ldap_err2string(rc)); \
    goto freeall; \
  }

#define aasprintf(fmt, ...) ({\
  int __len = 0;\
  char* __buffer;\
  __len = snprintf(NULL, 0, fmt, __VA_ARGS__); \
  __buffer = alloca(__len+1); \
  __len = snprintf(__buffer, __len+1, fmt, __VA_ARGS__); \
  __len>=0?__buffer: NULL; }) 



#if 0
static int do_sasl_interact(LDAP *l,unsigned flags,void *defaults,void *_interact)
{

  /*struct ldap_config *cfg=defaults;
  sasl_interact_t *interact=_interact;
  no fancy authzid, and GSSAPI doesn't need anything else */
  return LDAP_SUCCESS;
}
#endif
static char *no_attrs[]= {0};

static int verify_single_result(LDAP *l, int always_log, char *reason, LDAPMessage *messages)
{
  int rc, erc, num_entries;
  char *errmsg;

  rc = ldap_parse_result(l, messages, &erc, NULL, &errmsg,
			 NULL, NULL, 0);
  if (rc != LDAP_SUCCESS) {
    prtmsg("Failed to %s (parse_result): %s", reason, ldap_err2string(rc));
    return 0;
  }
  if (erc != LDAP_SUCCESS) {
    prtmsg("Failed to %s (server response): %s%s%s", reason, ldap_err2string(erc),
	   (errmsg?", ":""), (errmsg?errmsg:""));
    if (errmsg)
      ldap_memfree(errmsg);
    return 0;
  }
  if (errmsg)
    ldap_memfree(errmsg);
  num_entries=ldap_count_entries(l, messages);
  if (num_entries == 0) {
    if (always_log) 
      prtmsg("Failed to %s (no entries returned)", reason);
    return 0;
  }
  if (num_entries > 1) {
    prtmsg("Failed to %s (too many entries: %d)", reason, num_entries);
    return 0;
  }
  return 1;
}

static int verify_op_success(LDAP *l, char *reason, LDAPMessage *messages)
{
  int rc, erc;
  char *errmsg;

  rc = ldap_parse_result(l, messages, &erc, NULL, &errmsg,
			 NULL, NULL, 0);
  if (rc != LDAP_SUCCESS) {
    prtmsg("Failed to %s (parse_result): %s", reason, ldap_err2string(rc));
    return 0;
  }
  if (erc != LDAP_SUCCESS) {
    prtmsg("Failed to %s (server response): %s%s%s", reason, ldap_err2string(erc),
	   (errmsg?", ":""), (errmsg?errmsg:""));
    if (errmsg)
      ldap_memfree(errmsg);
    return 0;
  }
  if (errmsg)
    ldap_memfree(errmsg);
  return 1;
}

int is_admin_from_ldap(struct rekey_session *sess)
{
  static int ldap_initialized=0;
  char *username=NULL;
  LDAP *l=NULL;
  int v, ssl_hard=LDAP_OPT_X_TLS_HARD, rc, ret=0;
  struct timeval tv;
  LDAPMessage *response=NULL;
  char *reason, *filter;
  char *ldap_url, *ldap_base, *ldap_filter, *ldap_binddn;
  char *ldap_pwfile, *ldap_cacertdir;
  char ldap_pwbuf[257];
#ifdef HAVE_KRB5_REALM
  krb5_realm realm;
#else
  krb5_data rdata;
  krb5_data *realm = &rdata;
#endif
#if !defined(LDAP_OPT_X_TLS_PROTOCOL_MIN)
  SSL_CTX *sslctx;
#endif

  if (!princ_ncomp_eq(sess->kctx, sess->princ, 2) ||
      !compare_princ_comp(sess->kctx, sess->princ, 1, "admin")) {
    goto freeall;
  }

  if (!(username=dup_comp_string(sess->kctx, sess->princ, 0))) {
    prtmsg("Failed to extract username for admin check");
    goto freeall;
  }

#ifdef HAVE_KRB5_REALM
  realm=sess->realm;
#else
  rdata.data=sess->realm;
  rdata.length=strlen(sess->realm);
#endif
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_uri", 0, &ldap_url);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_base", 0, &ldap_base);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_group", 0, &rekey_admin_group);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_filter", USER_INGROUP_FILTER, &ldap_filter);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_binddn", LDAP_BINDDN, &ldap_binddn);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_pwfile", LDAP_PWFILE, &ldap_pwfile);
  krb5_appdefault_string(sess->kctx, "rekey", realm, "ldap_cacertdir", "/etc/andy/ldapcerts", &ldap_cacertdir);

  /*
   * These settings are now required.
   * No message is printed because that would be annoyingly noisy.
   */
  if (!ldap_url || !ldap_base || !rekey_admin_group) {
    goto freeall;
  }

  ldap_pwbuf[0] = 0;
  if (strlen(ldap_pwfile) > 0) {
    int fd=open(ldap_pwfile, O_RDONLY);
    ssize_t rsize;
    if (fd < 0) {
      prtmsg("Failed to open LDAP password file %s: %s", ldap_pwfile, strerror(errno));
      goto freeall;
    }
    rsize=read(fd, ldap_pwbuf, 256);
    if (rsize < 0) {
      prtmsg("Failed to read from LDAP password file %s: %s", ldap_pwfile, strerror(errno));
      goto freeall;
    }
    if (rsize > 255) {
      prtmsg("LDAP password file %s is too large. limit to 255 characters", ldap_pwfile);
      goto freeall;
    }
    while(rsize > 0 && isspace(ldap_pwbuf[rsize-1]))
      rsize--;
    ldap_pwbuf[rsize]=0;
  }
  if (!ldap_initialized) {
    LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ssl_hard);
    LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CACERTDIR, ldap_cacertdir);
    LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, "HIGH:!ADH:!eNULL:-SSLv2");
#if defined(LDAP_OPT_X_TLS_PROTOCOL_MIN)
    v=LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;
    LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_PROTOCOL_MIN, &v);
#else
    extern int ldap_pvt_tls_init();
    extern int ldap_pvt_tls_init_def_ctx( int is_server );
    ldap_pvt_tls_init();
    ldap_pvt_tls_init_def_ctx(0);
    LDAP_GET_OPTION(NULL, LDAP_OPT_X_TLS_CTX, &sslctx);
    if (sslctx) {
      SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
      SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
    }
#endif
    ldap_initialized=1;
  }
  errno=0;
  rc = ldap_initialize(&l, ldap_url);

  
  if (rc!=LDAP_SUCCESS)
  {
    prtmsg("Failed to initialize ldap for %s: %s%s%s", ldap_url,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
    goto freeall;
  }
  v=LDAP_VERSION3;
  LDAP_SET_OPTION(l, LDAP_OPT_PROTOCOL_VERSION, &v);
  LDAP_SET_OPTION(l, LDAP_OPT_X_TLS, &ssl_hard);

  errno=0;
#if 0
  rc = ldap_sasl_interactive_bind_s(l, NULL, "GSSAPI", NULL, NULL,
				    LDAP_SASL_QUIET, do_sasl_interact, NULL);
#else
  rc = ldap_bind_s(l, ldap_binddn, ldap_pwbuf, LDAP_AUTH_SIMPLE);
#endif
  if (rc!=LDAP_SUCCESS)
  {
    prtmsg("Failed to connect or authenticate to ldap for %s: %s%s%s", ldap_url,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
    goto freeall;
  }

  tv.tv_sec=30;
  tv.tv_usec=0;
  rc = ldap_search_ext_s(l, rekey_admin_group, LDAP_SCOPE_BASE, NO_FILTER,
			 no_attrs, 0, NULL, NULL, &tv, LDAP_NO_LIMIT, &response);
  if (rc != LDAP_SUCCESS) {
      prtmsg("Failed to verify group %s existence (searching): %s%s%s", rekey_admin_group,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
      goto freeall;
  }

  reason=aasprintf("verify group %s existence", rekey_admin_group);
  if (!verify_op_success(l, reason, response))
    goto freeall;
  ldap_msgfree(response);
  response=NULL;

  filter=aasprintf(ldap_filter, username, rekey_admin_group);
  rc = ldap_search_ext_s(l, ldap_base, LDAP_SCOPE_SUB, filter,
			 no_attrs, 0, NULL, NULL, &tv, LDAP_NO_LIMIT, &response);
  if (rc != LDAP_SUCCESS) {
      prtmsg("Failed to check user %s admin permission (searching): %s%s%s", username,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
      goto freeall;
  }

  reason=aasprintf("check user %s admin permission", username);
  if (!verify_single_result(l, 0, reason, response))
    goto freeall;

  ret=1;
 freeall:
  ldap_msgfree(response);
  if (l)
    ldap_unbind_ext_s(l, NULL, NULL);
  free(username);
  return ret;
}

  
