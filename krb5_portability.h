#ifdef HAVE_KRB5_KEYBLOCK_ENCTYPE
#define Z_keydata(keyblock)     ((keyblock)->contents)
#define Z_keylen(keyblock)      ((keyblock)->length)
#define Z_enctype(keyblock)     ((keyblock)->enctype)
#else
#define Z_keydata(keyblock)     ((keyblock)->keyvalue.data)
#define Z_keylen(keyblock)      ((keyblock)->keyvalue.length)
#define Z_enctype(keyblock)     ((keyblock)->keytype)
#endif
#ifdef HAVE_KRB5_KEYTAB_ENTRY_KEYBLOCK
#define kte_keyblock(kte) (&(kte)->keyblock)
#else
#define kte_keyblock(kte) (&(kte)->key)
#endif
#if defined(HAVE_KRB5_KT_FREE_ENTRY) && HAVE_DECL_KRB5_KT_FREE_ENTRY
#define krb5_free_keytab_entry_contents krb5_kt_free_entry
#elif defined(HAVE_KRB5_FREE_KEYTAB_ENTRY_CONTENTS)
/* nothing */
#else
static inline int krb5_free_keytab_entry_contents(krb5_context ctx,
                                                  krb5_keytab_entry *ent) {
  krb5_free_principal(ctx, ent->principal);
  krb5_free_keyblock_contents(ctx, kte_keyblock(ent));
  return 0;
}
#endif

#ifndef HAVE_KRB5_GET_ERR_TEXT
#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#else
#ifdef HAVE_ET_COM_ERR_H
#include <et/com_err.h>
#endif
#endif
#define krb5_get_err_text(c, r) error_message(r)
#endif
#if defined(HAVE_KRB5_C_MAKE_RANDOM_KEY) && !defined(HAVE_KRB5_GENERATE_RANDOM_KEYBLOCK)
#define krb5_generate_random_keyblock krb5_c_make_random_key
#endif
