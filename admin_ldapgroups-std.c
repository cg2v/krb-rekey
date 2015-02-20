#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <alloca.h>
#include <stdarg.h>
#include <ldap.h>
#include <errno.h>
#include <sasl/sasl.h>
#include <openssl/ssl.h>

#define SESS_PRIVATE
#define NEED_KRB5
#include "rekeysrv-locl.h"
#define REKEY_ADMIN_GROUP "cn=cmu:pgh:ComputingServices:ISAM:KerberosRekeyManagers,ou=groups,dc=cmu,dc=edu"
#define LDAP_URI "ldaps://ldap.cmu.edu"
#define LDAP_BASEDN "dc=cmu,dc=edu"
#define NO_FILTER "(objectClass=*)"
#define USER_INGROUP_FILTER "(&(uid=%s)(isMemberOf=%s))"


static char *rekey_admin_group=REKEY_ADMIN_GROUP;
char *admin_help_string = "admin LDAP group";

void admin_arg(char *arg)
{
  rekey_admin_group = arg;
}
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



static int do_sasl_interact(LDAP *l,unsigned flags,void *defaults,void *_interact)
{

  /*struct ldap_config *cfg=defaults;
  sasl_interact_t *interact=_interact;
  no fancy authzid, and GSSAPI doesn't need anything else */
  return LDAP_SUCCESS;
}

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

int is_admin(struct rekey_session *sess)
{
  char *username=NULL;
  LDAP *l=NULL;
  int v, ssl_hard=LDAP_OPT_X_TLS_HARD, rc, ret=0;
  struct timeval tv;
  LDAPMessage *response=NULL;
  char *reason, *filter;
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

  LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ssl_hard);
  LDAP_SET_OPTION(NULL, LDAP_OPT_X_TLS_CACERTDIR, "/etc/andy/ldapcerts");
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

  errno=0;
  rc = ldap_initialize(&l, LDAP_URI);

  
  if (rc!=LDAP_SUCCESS)
  {
    prtmsg("Failed to initialize ldap for %s: %s%s%s", LDAP_URI,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
    goto freeall;
  }
  v=LDAP_VERSION3;
  LDAP_SET_OPTION(l, LDAP_OPT_PROTOCOL_VERSION, &v);
  LDAP_SET_OPTION(l, LDAP_OPT_X_TLS, &ssl_hard);

  errno=0;
  rc = ldap_sasl_interactive_bind_s(l, NULL, "GSSAPI", NULL, NULL,
				    LDAP_SASL_QUIET, do_sasl_interact, NULL);
  if (rc!=LDAP_SUCCESS)
  {
    prtmsg("Failed to connect or authenticate to ldap for %s: %s%s%s", LDAP_URI,
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
  if (!verify_single_result(l, 1, reason, response))
    goto freeall;
  ldap_msgfree(response);
  response=NULL;

  filter=aasprintf(USER_INGROUP_FILTER, username, rekey_admin_group);
  rc = ldap_search_ext_s(l, LDAP_BASEDN, LDAP_SCOPE_SUB, filter,
			 no_attrs, 0, NULL, NULL, &tv, LDAP_NO_LIMIT, &response);
  if (rc != LDAP_SUCCESS) {
      prtmsg("Failed to verify group %s existence (searching): %s%s%s", rekey_admin_group,
	   ldap_err2string(rc),(errno==0)?"":": ",
	   (errno==0)?"":strerror(errno));
      goto freeall;
  }

  reason=aasprintf("check user %s", username);
  if (!verify_single_result(l, 1, reason, response))
    goto freeall;

  ret=1;
 freeall:
  ldap_msgfree(response);
  if (l)
    ldap_unbind_ext_s(l, NULL, NULL);
  free(username);
  return ret;
}

  
