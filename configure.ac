#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(KRB-REKEY, 1.2, n-a@n-a)
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([rekey-locl.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
gl_EARLY
AX_CFLAGS_WARN_ALL
AX_C___ATTRIBUTE__
gl_INIT
AC_DEFINE([REPLACE_VASNPRINTF], [1], [rename vasnprintf to avoid cross-library api conflicts])
# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h getopt.h memory.h])
AC_CHECK_FUNCS([daemon setsid setpgrp])
AC_FUNC_SETPGRP
# Checks for libraries.
AC_ARG_ENABLE(server, AS_HELP_STRING([--enable-server], [build server component (default is no)]),
	[build_server=$enableval], [build_server=no])
AC_ARG_ENABLE(kadm5-client, AS_HELP_STRING([--enable-kadm5-client],
              [use kadmin client mode]),
              [use_kadm5_client=$enableval],
              [use_kadm5_client=no])
AC_ARG_WITH(ldap, AS_HELP_STRING([--with-ldap], [support LDAP for admin ACL]),
            [], [with_ldap=check])
AC_ARG_WITH(default-service-principal,
            AS_HELP_STRING([--with-default-service-principal=princ],
                           [default Kerberos principal for server]),
            [def_rekey_service="'$withval'"
             AC_DEFINE_UNQUOTED([REKEY_DEF_SERVICE], ["$withval"])],
            [def_rekey_service="the same as specifying '-'"
             AC_DEFINE([REKEY_DEF_SERVICE], [NULL],
                       [Default rekey server Kerberos principal])])
AC_SUBST([def_rekey_service])

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
save_LIBS="$LIBS"
LIBS="$LIB_KRB5 $LIBS"
AC_CHECK_LIB([asn1], [decode_Ticket], [LIB_ASN1=-lasn1])
AC_SUBST([LIB_ASN1])
LIBS="$save_LIBS"

PKG_CHECK_MODULES([SSL], [openssl])
save_LIBS="$LIBS"
LIBS="$SSL_LIBS $LIBS"
AC_CHECK_FUNCS([ERR_load_crypto_strings ERR_print_errors_cb CRYPTO_cleanup_all_ex_data])
LIBS="$save_LIBS"
AC_DEFINE([OPENSSL_NO_KRB5], [], [Prevent openssl headers from trying to import kerberos headers])

LIB_SQLITE3=
LIB_LDAP=
LIB_KADMS=

if test "$build_server" = "yes"; then
  if test "$use_kadm5_client" = "yes"; then
    LIB_KADMS=`$KRB5CONF --libs kadm-client`
  else
    LIB_KADMS=`$KRB5CONF --libs kadm-server`
  fi

  AC_CHECK_LIB([sqlite3], [sqlite3_open], [LIB_SQLITE3=-lsqlite3],[
  AC_MSG_ERROR([No sqlite library found])])
  
  if test "x$with_ldap" != xno; then
    AC_CHECK_LIB([ldap], [ldap_initialize], [], [
      if test "x$with_ldap" != xcheck ; then 
        AC_MSG_ERROR([No ldap library found])
      else
        with_ldap=no
      fi])
  fi
  dnl sasl library not needed - included by ldap
  if test "x$with_ldap" != xno; then
    AC_CHECK_HEADERS([ldap.h sasl/sasl.h], [], [
      if test "x$with_ldap" != xcheck ; then 
        AC_MSG_ERROR([LDAP or SASL headers missing])
      else
        with_ldap=no
      fi])
  fi
  if test "x$with_ldap" != xno; then
    LIB_LDAP=-lldap
    AC_DEFINE([HAVE_LDAP], [1], [Define if you have LDAP libraries])
  fi

  AC_SUBST([SERVER_PROG], ['rekeysrv${EXEEXT}'])
fi

AM_CONDITIONAL([SERVER], [test "x$build_server" = xyes])
AM_CONDITIONAL([LDAP_GROUPS], [test "x$with_ldap" != xno])
AC_SUBST([LIB_KADMS])
AC_SUBST([LIB_SQLITE3])
AC_SUBST([LIB_LDAP])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$KRB_INC_FLAGS $CPPFLAGS"
AC_CHECK_HEADERS([gssapi/gssapi.h gssapi/gssapi_krb5.h], [], [AC_CHECK_HEADERS([gssapi.h],[AC_DEFINE([USE_GSSAPI_H],[],[Use heimdal-style <gssapi.h>, not <gssapi/gssapi_*.h>])],[AC_MSG_ERROR([No GSSAPI headers found])])])
AC_CHECK_HEADERS([krb5.h],[],[AC_CHECK_HEADERS([krb5/krb5.h],[],[AC_MSG_ERROR([No krb5 headers found])])])
AC_CHECK_HEADERS([com_err.h],[],[AC_CHECK_HEADERS([et/com_err.h],[],[no_com_err=yes])])
if test "$build_server" = "yes"; then
AC_CHECK_HEADERS([kadm5/kadm5_err.h])
fi
CPPFLAGS="$save_CPPFLAGS"


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
AC_CHECK_TYPES([krb5_realm, krb5_kt_ops], , , [#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
AC_CHECK_DECLS([krb5_get_error_message, krb5_free_error_message, krb5_get_error_string, krb5_free_error_string, krb5_get_err_text, krb5_generate_random_keyblock, krb5_c_make_random_key, krb5_principal_get_realm, krb5_principal_get_comp_string, krb5_princ_realm, krb5_princ_component, krb5_free_unparsed_name, krb5_free_keytab_entry_contents, krb5_kt_free_entry, krb5_xfree, krb5_kt_register, krb5_ktf_writable_ops, krb5_enctype_valid, krb5_c_valid_enctype, ENCTYPE_DES_CBC_CRC, ENCTYPE_DES3_CBC_SHA1, ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_ARCFOUR_HMAC],[],[],[#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif])
LIB_COM_ERR=
if test "X$ac_cv_have_decl_krb5_get_err_text" = "Xno"; then
   AC_CHECK_FUNCS([error_message])
   if test "X$no_com_err" = "Xyes"; then
      AC_MSG_ERROR([No com_err headers found, and krb5 doesn't provide krb5_get_err_text])
   else
      if test "X$ac_cv_func_error_message" = "Xno"; then
         AC_CHECK_LIB([com_err], [error_message], [LIB_COM_ERR=-lcom_err], [AC_MSG_ERROR([No com_err library found, and krb5 doesn't provide krb5_get_err_text])])
      fi
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
AC_MSG_CHECKING([for krb5_ktf_writable_ops])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif
#ifdef HAVE_KRB5_KT_OPS
#if !HAVE_DECL_KRB5_KT_REGISTER
krb5_error_code krb5_kt_register(krb5_context, krb5_kt_ops *);
#endif
#if !HAVE_DECL_KRB5_KTF_WRITABLE_OPS
extern krb5_kt_ops krb5_ktf_writable_ops;
#endif
#endif
]], [[#if !defined(HAVE_KRB5_KT_OPS) || !HAVE_DECL_KRB5_KT_REGISTER
#error Missing prerequisites for dynamic keytab backends - WRFILE must be built-in
#else
krb5_context c = 0;
krb5_kt_register(c, &krb5_ktf_writable_ops);
#endif]])],
[ktf_writable_ops="yes"],[ktf_writable_ops="no"])
AC_MSG_RESULT([$ktf_writable_ops])
if test X$ktf_writable_ops = Xyes; then 
	AC_DEFINE([HAVE_KRB5_KTF_WRITABLE_OPS], [], 
[Define if the krb5_ktf_writable_ops struct is available])
fi
AC_MSG_CHECKING([whether krb5_enctype_valid/krb5_c_valid_enctype works])
dnl Make sure the function returns both positive and negative 
dnl results for some value between 0 and 32
dnl Make sure that only one of the mutually exclusive styles
dnl (boolean vs error) is used.
dnl The next test will determine which style we have.
AC_RUN_IFELSE([AC_LANG_PROGRAM([[#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif
#if HAVE_DECL_KRB5_C_VALID_ENCTYPE && !HAVE_DECL_KRB5_ENCTYPE_VALID
#define krb5_enctype_valid(ctx, et) krb5_c_valid_enctype((et))
#endif]],[[krb5_context c; int i; int ret; 
int got0=0; int got1=0; int gotother=0;
if (krb5_init_context(&c)) return 1;
for (i=0; i < 32; i++) {
    ret=krb5_enctype_valid(c, i);
    if (ret == 0)
       got0=1;
    if (ret == 1)
       got1=1;
    if (ret < 0 || ret > 1)
       gotother=1;
}
if (got0 == 0)
  return 1;
if ((got1 | gotother) == 0)
  return 2;
if (got1 == gotother)
  return 3;
return 0;]])], [ enctype_valid_works=yes ], [enctype_valid_works=no],
[enctype_valid_works=cross-compiling-no])
AC_MSG_RESULT([$enctype_valid_works])
if test $enctype_valid_works = yes; then
     AC_MSG_CHECKING([return style of krb5_enctype_valid/krb5_c_valid_enctype])
     AC_RUN_IFELSE([AC_LANG_PROGRAM([[#ifdef HAVE_KRB5_H
#include <krb5.h>
#else
#include <krb5/krb5.h>
#endif
#if HAVE_DECL_KRB5_C_VALID_ENCTYPE && !HAVE_DECL_KRB5_ENCTYPE_VALID
#define krb5_enctype_valid(ctx, et) krb5_c_valid_enctype((et))
#endif]],[[krb5_context c; int i, ret; 
if (krb5_init_context(&c)) return 1;
for (i=0; i < 32; i++) {
    ret=krb5_enctype_valid(c, i);
    if (ret > 1 || ret < 0)
	return 1;
}
return 0;]])], [ enctype_valid_type=boolean ], [enctype_valid_type=error_code],
[enctype_valid_type=cross-compiling-unknown])
     AC_MSG_RESULT([$enctype_valid_type])
     if test $enctype_valid_type = boolean; then
        AC_DEFINE([ENCTYPE_VALID_RETURNS_BOOLEAN], [], [Define if krb5_enctype_valid or krb5_c_valid_enctype returns a boolean value])
     fi
     if test $enctype_valid_type = error_code; then
        AC_DEFINE([ENCTYPE_VALID_RETURNS_ERROR_CODE], [], [Define if krb5_enctype_valid or krb5_c_valid_enctype returns an error code])
     fi
else
     AC_DEFINE([BROKEN_ENCTYPE_VALIDITY], [], [Define if the return semantics of krb5_enctype_valid or krb5_c_valid_enctype cannot be determined])
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
AC_TRY_LINK([#include <kadm5/admin.h>], [krb5_context kctx;
kadm5_config_params *pa = 0;
void *h; char *dbp[2] = { "", 0};
(void)kadm5_init_with_skey(kctx, "", "", KADM5_ADMIN_SERVICE, pa,
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
