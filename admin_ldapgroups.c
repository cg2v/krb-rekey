#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdarg.h>
#include <groups.h>

#define SESS_PRIVATE
#define NEED_KRB5
#include "rekeysrv-locl.h"
#define REKEY_ADMIN_GROUP "cn=cmu:pgh:ComputingServices:ISAM:KerberosRekeyManagers,ou=group,dc=cmu,dc=edu"

static char *rekey_admin_group=REKEY_ADMIN_GROUP;

int is_admin(struct rekey_session *sess)
{
  char *username=NULL;
  GROUPS *g=NULL;
  int rc, ret=0;

  if (!princ_ncomp_eq(sess->kctx, sess->princ, 2) ||
      !compare_princ_comp(sess->kctx, sess->princ, 1, "admin")) {
    goto freeall;
  }

  if (!(username=dup_comp_string(sess->kctx, sess->princ, 0))) {
    prtmsg("Failed to extract username for admin check");
    goto freeall;
  }

  g = groups_init();
  if (!g) {
    prtmsg("Cannot initialize groups library");
    goto freeall;
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
      groups_config(g, GROUPS_FLAG_NOAUTH, NULL) ||
      groups_config(g, GROUPS_FLAG_RECURSE, NULL)) {
    prtmsg("Cannot configure groups library: %s", groups_error(g));
    goto freeall;
  }
#else
  prtmsg("No SSL/TLS support in <groups.h>. authz checks will not be trustworthy");
  if (groups_config(g, GROUPS_FLAG_NOAUTH, NULL) ||
      groups_config(g, GROUPS_FLAG_RECURSE, NULL)) {
    prtmsg("Cannot configure groups library: %s", groups_error(g));
    goto freeall;
  }
#endif
  
  rc = groups_anyuser_in(g, username, rekey_admin_group, "owner",
                         GROUPS_ANYUSER_ANDREW | GROUPS_ANYUSER_TRYAUTHENT |
                         GROUPS_ANYUSER_NOPTS);
  
  if (rc < 0)
    prtmsg("Unable to check group membership: %s", groups_error(g));
  else
    ret = (rc > 0);
 freeall:
  if (g) groups_destroy(g);
  free(username);
  return ret;
}
