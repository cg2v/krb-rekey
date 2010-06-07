#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(KRB-REKEY, 0.6, n-a@n-a)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([rekey-locl.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
gl_EARLY
AX_CFLAGS_WARN_ALL
gl_INIT
AC_DEFINE([REPLACE_VASNPRINTF], [1], [rename vasnprintf to avoid cross-library api conflicts])
# Checks for libraries.
dnl AC_CHECK_LIB([gssapi], [gss_init_sec_context], [LIB_GSS=-lgssapi],[
dnl AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context], [LIB_GSS=-lgssapi_krb5],[
dnl AC_MSG_ERROR([No GSSAPI library found])])])
dnl AC_CHECK_LIB([krb5], [krb5_init_context], [LIB_KRB5=-lkrb5],[
dnl AC_MSG_ERROR([No krb5 library found])])
AC_ARG_ENABLE(server, AS_HELP_STRING([--enable-server], [build server component (default is no)]),
	[build_server=$enableval], [build_server=no])
AC_CHECK_PROG([KRB5CONF], [krb5-config], [krb5-config])
if test X$KRB5CONF = X; then
   AC_MSG_ERROR([krb5-config not found. update path or set KRB5CONF before running configure])
fi
KRB_INC_FLAGS=`$KRB5CONF --cflags`
AC_SUBST([KRB_INC_FLAGS])
LIB_GSS=`$KRB5CONF --libs gssapi`
AC_SUBST([LIB_GSS])
if test "X$LIB_GSS" = "X"; then
   AC_MSG_ERROR([krb5-config does not support GSSAPI])
fi
LIB_KRB5=`$KRB5CONF --libs`
AC_SUBST([LIB_KRB5])
AC_CHECK_LIB([crypto], [ERR_load_crypto_strings], [LIB_CRYPTO=-lcrypto])
save_LIBS="$LIBS"
LIBS="$LIB_CRYPTO $LIBS"
AC_CHECK_FUNCS([ERR_print_errors_cb CRYPTO_cleanup_all_ex_data])
LIBS="$save_LIBS"
AC_CHECK_LIB([ssl], [SSL_library_init], [LIB_SSL="-lssl $LIB_CRYPTO"], [
AC_SUBST([LIB_SSL])
AC_MSG_ERROR([No openssl library found])])
AC_DEFINE([OPENSSL_NO_KRB5], [], [Prevent openssl headers from trying to import kerberos headers])

LIB_SQLITE3=
LIB_GROUPS=
LIB_KADMS=

if test "$build_server" = "yes"; then
LIB_KADMS=`$KRB5CONF --libs kadm-server`
AC_CHECK_LIB([sqlite3], [sqlite3_open], [LIB_SQLITE3=-lsqlite3],[
AC_MSG_ERROR([No sqlite library found])])
AC_CHECK_LIB([groups], [groups_anyuser_in], [LIB_GROUPS=-lgroups], [
AC_MSG_ERROR([No ldap groups library found])])
AC_SUBST([SERVER_PROG], ['rekeysrv${EXEEXT}'])
fi

AC_SUBST([LIB_KADMS])
AC_SUBST([LIB_SQLITE3])
AC_SUBST([LIB_GROUPS])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h memory.h netdb.h])
save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$KRB_INC_FLAGS $CPPFLAGS"
AC_CHECK_HEADERS([gssapi/gssapi.h gssapi/gssapi_krb5.h], [AC_DEFINE([HEADER_GSSAPI_GSSAPI],[],[Define if mit-style gss headers are in use])], [AC_CHECK_HEADERS([gssapi.h],[],[AC_MSG_ERROR([No GSSAPI headers found])])])
AC_CHECK_HEADERS([krb5.h],[],[AC_CHECK_HEADERS([krb5/krb5.h],[],[AC_MSG_ERROR([No krb5 headers found])])])
AC_CHECK_HEADERS([com_err.h],[],[AC_CHECK_HEADERS([et/com_err.h],[],[no_com_err=yes])])
if test "$build_server" = "yes"; then
AC_CHECK_HEADERS([kadm5/kadm5_err.h])
fi
CPPFLAGS="$save_CPPFLAGS"


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $KRB_INC_FLAGS"
AC_CHECK_MEMBER([krb5_keyblock.enctype],
  [AC_DEFINE([HAVE_KRB5_KEYBLOCK_ENCTYPE], [],
    [Define if struct krb5_keyblock has member 'enctype'])], [],
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
AC_CHECK_MEMBER([krb5_keyblock.keytype],
  [AC_DEFINE([HAVE_KRB5_KEYBLOCK_KEYTYPE], [],
    [Define if struct krb5_keyblock has member 'keytype'])], [], 
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
if test X$ac_cv_member_krb5_keyblock_enctype != Xyes && test X$ac_cv_member_krb5_keyblock_keytype != Xyes; then
	AC_MSG_ERROR([Cannot figure out how struct keyblock works])
fi
AC_CHECK_MEMBER([krb5_keytab_entry.keyblock],
  [AC_DEFINE([HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK], [],
    [Define if struct krb5_keyblock has member 'keyblock'])], [], 
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
AC_CHECK_MEMBER([krb5_keytab_entry.key],
  [AC_DEFINE([HAVE_KRB5_KEYTAB_ENTRY_KEY], [],
    [Define if struct krb5_keyblock has member 'key'])], [], 
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
if test X$ac_cv_member_krb5_keytab_entry_keyblock != Xyes && test X$ac_cv_member_krb5_keytab_entry_key != Xyes; then
	AC_MSG_ERROR([Cannot figure out how struct keytab_entry works])
fi
AC_CHECK_MEMBER([krb5_ticket.enc_part2],
  [AC_DEFINE([HAVE_KRB5_TICKET_ENC_PART2], [],
    [Define if struct krb5_ticket has member 'enc_part2'])], [], 
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
AC_CHECK_MEMBER([krb5_ticket.ticket],
  [AC_DEFINE([HAVE_KRB5_TICKET_TICKET], [],
    [Define if struct krb5_ticket has member 'ticket'])], [], 
     [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
if test X$ac_cv_member_krb5_ticket_enc_part2 != Xyes && test X$ac_cv_member_krb5_ticket_ticket != Xyes; then
	AC_MSG_ERROR([Cannot figure out how struct krb5_ticket works])
fi
CPPFLAGS="$save_CPPFLAGS"

save_LIBS="$LIBS"
LIBS="$LIB_KRB5 $LIBS"
save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$KRB_INC_FLAGS $CPPFLAGS"
AC_CHECK_TYPES([krb5_realm], , , [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
AC_CHECK_FUNCS([krb5_get_error_message krb5_get_error_string krb5_get_err_text krb5_generate_random_keyblock krb5_c_make_random_key krb5_principal_get_realm krb5_principal_get_comp_string krb5_free_unparsed_name krb5_free_keytab_entry_contents krb5_kt_free_entry krb5_xfree])
AC_CHECK_DECLS([krb5_get_error_message, krb5_get_error_string, krb5_get_err_text, krb5_generate_random_keyblock, krb5_c_make_random_key, krb5_principal_get_realm, krb5_principal_get_comp_string, krb5_princ_realm, krb5_princ_component, krb5_free_unparsed_name, krb5_free_keytab_entry_contents, krb5_kt_free_entry, krb5_xfree],[],[],[#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
LIB_COM_ERR=
if test "X$ac_cv_func_krb5_get_err_text" = "Xno"; then
   if test "X$have_com_err" = "Xno"; then
      AC_MSG_ERROR([No com_err headers found, and krb5 doesn't provide krb5_get_err_text])
   else
      AC_CHECK_LIB([com_err], [error_message], [LIB_COM_ERR=-lcom_err], [AC_MSG_ERROR([No com_err library found, and krb5 doesn't provide krb5_get_err_text])])
   fi
fi
AC_SUBST([LIB_COM_ERR])

AC_MSG_CHECKING([for krb5_princ_component])
AC_TRY_LINK([#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif], [krb5_context c = 0;
krb5_principal p=0; (void)krb5_princ_component(c, p, 1);],
 [ x_krb5_princ_component=yes ], [ x_krb5_princ_component=no ])
AC_MSG_RESULT([$x_krb5_princ_component])
if test X$x_krb5_princ_component = Xyes; then
  AC_DEFINE([HAVE_KRB5_PRINC_COMPONENT], [], [Define if krb5_princ_component function/macro is available])
fi
AC_MSG_CHECKING([for krb5_princ_realm])
AC_TRY_LINK([#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif], [krb5_context c = 0;
krb5_principal p=0; (void)krb5_princ_realm(c, p);],
 [ x_krb5_princ_realm=yes ], [ x_krb5_princ_realm=no ])
AC_MSG_RESULT([$x_krb5_princ_realm])
if test X$x_krb5_princ_realm = Xyes; then
  AC_DEFINE([HAVE_KRB5_PRINC_REALM], [], [Define if krb5_princ_realm function/macro is available])
fi
if test "$build_server" = "yes"; then
LIBS="$LIB_KADMS $save_LIBS"
AC_MSG_CHECKING([for compatible kadm5_init_with_skey_ctx])
AC_TRY_LINK([#include <kadm5/admin.h>], [krb5_context c = 0;
kadm5_config_params *pa = 0;
void *h;
(void)kadm5_init_with_skey_ctx(c, "", "", KADM5_ADMIN_SERVICE, pa,
   KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, &h);],
 [ x_kadm5_init_with_skey_ctx=yes ], [ x_kadm5_init_with_skey_ctx=no ])
AC_MSG_RESULT([$x_kadm5_init_with_skey_ctx])
if test X$x_kadm5_init_with_skey_ctx = Xyes; then
  AC_DEFINE([HAVE_KADM5_INIT_WITH_SKEY_CTX], [], [Define if kadm5_init_with_skey_ctx function is available with heimdal-compatible signature])
fi
AC_MSG_CHECKING([for compatible kadm5_init_with_skey])
AC_TRY_LINK([#include <kadm5/admin.h>], [kadm5_config_params *pa = 0;
void *h; char *dbp[2] = { "", 0};
(void)kadm5_init_with_skey("", "", KADM5_ADMIN_SERVICE, pa,
   KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, dbp, &h);],
 [ x_kadm5_init_with_skey=yes ], [ x_kadm5_init_with_skey=no ])
AC_MSG_RESULT([$x_kadm5_init_with_skey])
if test X$x_kadm5_init_with_skey = Xyes; then
  AC_DEFINE([HAVE_KADM5_INIT_WITH_SKEY], [], [Define if kadm5_init_with_skey function is available with MIT-compatible signature])
fi
if test X$x_kadm5_init_with_skey_ctx != Xyes && test X$x_kadm5_init_with_skey != Xyes; then
	AC_MSG_ERROR([Cannot figure out how kadm5_init_with_skey works])
fi
AC_MSG_CHECKING([for compatible kadm5_chpass_principal_with_key])
AC_TRY_LINK([#include <kadm5/admin.h>], [krb5_principal p = 0;
krb5_key_data k[2];
void *h=0;
(void)kadm5_chpass_principal_with_key(h, p, 1, k);],
 [ x_kadm5_chpass_principal_with_key=yes ], [ x_kadm5_chpass_principal_with_key=no ])
AC_MSG_RESULT([$x_kadm5_chpass_principal_with_key])
if test X$x_kadm5_chpass_principal_with_key = Xyes; then
  AC_DEFINE([HAVE_KADM5_CHPASS_PRINCIPAL_WITH_KEY], [], [Define if kadm5_chpass_principal_with_key function is available with heimdal-compatible signature])
fi
AC_MSG_CHECKING([for compatible kadm5_setkey_principal])
AC_TRY_LINK([#include <kadm5/admin.h>], [krb5_principal p = 0;
krb5_keyblock k[2];
void *h=0;
(void)kadm5_setkey_principal(h, p, k, 2);],
 [ x_kadm5_setkey_principal=yes ], [ x_kadm5_setkey_principal=no ])
AC_MSG_RESULT([$x_kadm5_setkey_principal])
if test X$x_kadm5_setkey_principal = Xyes; then
  AC_DEFINE([HAVE_KADM5_SETKEY_PRINCIPAL], [], [Define if kadm5_setkey_principal function is available with MIT-compatible signature])
fi
if test X$x_kadm5_chpass_principal_with_key != Xyes && test X$x_kadm5_setkey_principal != Xyes; then
	AC_MSG_ERROR([Cannot figure out how to set keys with kadm library])
fi
fi

LIBS="$save_LIBS"
CPPFLAGS="$save_CPPFLAGS"
AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
