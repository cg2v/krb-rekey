#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif
#include "krb5_portability.h"

struct principal_struct;
typedef struct principal_struct {
  krb5_principal name;
  char *print_name;
  int last_vno;
  int max_vno;
  int min_vno;
  time_t max_timestamp;
  time_t est_lifetime;
  int kdc_vno;
  int mult_vno;
  int min_enctype;
  int max_enctype;
  struct principal_struct *next;
} principal;

void process_entry(krb5_context ctx, krb5_keytab_entry *entry,
		   principal **princ_list) {
  krb5_error_code rc;
  principal *tmp;
  
  for (tmp=*princ_list;tmp;tmp=tmp->next) {
    if (krb5_principal_compare(ctx, entry->principal, tmp->name))
      break;
  }
  if (tmp) {
    if (tmp->last_vno != entry->vno)
      tmp->mult_vno++;
    tmp->last_vno = entry->vno;
    if (entry->vno > tmp->max_vno) {
      tmp->max_vno = entry->vno;
      tmp->max_timestamp = entry->timestamp;
    }
    if (entry->vno < tmp->min_vno) {
      tmp->min_vno = entry->vno;
    }
    if (Z_enctype(kte_keyblock(entry)) < tmp->min_enctype) {
      tmp->min_enctype = Z_enctype(kte_keyblock(entry));
    } 
    if (Z_enctype(kte_keyblock(entry)) > tmp->max_enctype) {
      tmp->max_enctype = Z_enctype(kte_keyblock(entry));
    } 
  } else {
    tmp = calloc(1, sizeof(principal));
    if (!tmp) {
      fprintf(stderr, "Cannot allocate memory!\n");
      exit(1);
    }
    rc = krb5_copy_principal(ctx, entry->principal,
			     &tmp->name);
    if (rc) {
      fprintf(stderr, "Cannot allocate memory while copying principal!\n");
      exit(1);
    }
    rc = krb5_unparse_name(ctx, tmp->name, &tmp->print_name);
    if (rc) {
      fprintf(stderr, "Cannot allocate memory while copying principal!\n");
      exit(1);
    }
    tmp->max_vno = tmp->min_vno = tmp->last_vno = entry->vno;
    tmp->max_timestamp = entry->timestamp;
    tmp->max_enctype = tmp->min_enctype = Z_enctype(kte_keyblock(entry));
    tmp->next=*princ_list;
    *princ_list=tmp;
  }
}
    
int enumerate_keytab(krb5_context ctx, krb5_keytab keytab, 
		     principal **princ_list) {

  krb5_error_code rc;
  krb5_keytab_entry entry;
  krb5_kt_cursor kt_c;

  if (krb5_kt_start_seq_get(ctx, keytab, &kt_c)) {
    fprintf(stderr, "Cannot read from keytab\n");
    exit(1);
  }

  while (0 == krb5_kt_next_entry(ctx, keytab, &entry, &kt_c)) {
    process_entry(ctx, &entry, princ_list);
    krb5_free_keytab_entry_contents(ctx, &entry);
  }
  krb5_kt_end_seq_get(ctx, keytab, &kt_c);
  return 0;
}

void print_krb5_error(krb5_context ctx, FILE *dest, char *pfx, 
		      principal *target, krb5_error_code rc) {
  const char *errtext;
#if HAVE_DECL_KRB5_GET_ERROR_MESSAGE && HAVE_DECL_KRB5_FREE_ERROR_MESSAGE
  errtext = krb5_get_error_message(ctx, rc);
#else
#if HAVE_DECL_KRB5_GET_ERROR_STRING && HAVE_DECL_FREE_KRB5_ERROR_STRING
  char *free_err=NULL;
  if (krb5_have_error_string(ctx)) {
    free_err = krb5_get_error_string(ctx);
    errtext = free_err;
  } else 
#endif
    errtext = krb5_get_err_text(ctx, rc);
#endif
  if (target)
    fprintf(dest, "%s while processing %s: %s\n",
	    pfx, target->print_name, errtext);
  else
    fprintf(dest, "%s: %s\n", pfx, errtext);
#if HAVE_DECL_KRB5_GET_ERROR_MESSAGE && HAVE_DECL_KRB5_FREE_ERROR_MESSAGE
  krb5_free_error_message(ctx, errtext);
#else
#if HAVE_DECL_KRB5_GET_ERROR_STRING && HAVE_DECL_FREE_KRB5_ERROR_STRING
  if (free_err)
    krb5_free_error_string(ctx, free_err);
#endif
#endif
}
  
int get_correct_vno(krb5_context ctx, krb5_keytab kt, 
		    principal *princ_to_check) {

  krb5_error_code rc;
  krb5_ccache cc=NULL;
  krb5_creds cr, *outcr=NULL;
  krb5_auth_context cli_actx=NULL, srv_actx=NULL;
  krb5_data authent;
  krb5_ticket *ticket=NULL;
  krb5_flags ret_flags;
  int ret=1;

  memset(&cr, 0, sizeof(krb5_creds));
  memset(&authent, 0, sizeof(krb5_data));
  rc=krb5_cc_default(ctx, &cc);
  if (rc) {
    print_krb5_error(ctx, stderr, "Cannot get user default ticket cache", NULL, rc);
    goto cleanup;
  }

  rc = krb5_cc_get_principal(ctx, cc, &cr.client);
  if (rc) {
    print_krb5_error(ctx, stderr, "Ticket file empty (cannot get client name)",  princ_to_check, rc);
    goto cleanup;
  }
  rc = krb5_auth_con_init(ctx, &cli_actx);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot init auth context)", NULL, rc);
    goto cleanup;
  }

  rc = krb5_auth_con_setflags(ctx, cli_actx, 0);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot init auth context)", NULL, rc);
    goto cleanup;
  }

  rc=krb5_copy_principal(ctx, princ_to_check->name, &cr.server);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot copy principal)", NULL, rc);
    goto cleanup;
  }

  rc = krb5_get_credentials(ctx, 0, cc, &cr, &outcr);
  if (rc) {
    print_krb5_error(ctx, stderr, "Cannot get ticket from kdc", princ_to_check, rc);
    goto cleanup;
  }
    
  rc = krb5_mk_req_extended(ctx, &cli_actx, 0, NULL,
			    outcr, &authent);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot make authenticator)", NULL, rc);
    goto cleanup;
  }

  rc = krb5_auth_con_init(ctx, &srv_actx);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot init auth context)", NULL, rc);
    goto cleanup;
  }

  rc = krb5_auth_con_setflags(ctx, srv_actx, 0);
  if (rc) {
    print_krb5_error(ctx, stderr, "Internal error (Cannot init auth context)", NULL, rc);
    goto cleanup;
  }

  rc = krb5_rd_req(ctx, &srv_actx, &authent, NULL, kt, &ret_flags, &ticket);
  if (rc == KRB5KRB_AP_ERR_BAD_INTEGRITY ||
      rc == KRB5KRB_AP_ERR_MODIFIED ||
      rc == KRB5KRB_AP_ERR_NOKEY ||
      rc == KRB5KRB_AP_ERR_BADKEYVER ||
      rc == KRB5_CC_NOTFOUND ||
      rc == KRB5_CC_END) {
    fprintf(stderr, "Could not decrypt ticket for %s: correct key probably not present in keytab\n", princ_to_check->print_name);
    goto cleanup;
  }
  if (rc) {
    print_krb5_error(ctx, stderr, "Could not decrypt authenticator", princ_to_check, rc);
    goto cleanup;
  }

#ifdef HAVE_KRB5_TICKET_ENC_PART2
  princ_to_check->kdc_vno = ticket->enc_part.kvno;
  princ_to_check->est_lifetime = ticket->enc_part2->times.endtime - 
    ticket->enc_part2->times.authtime;
#else
  {
      Ticket enc_tkt;
      size_t out_len;
      rc = decode_Ticket(outcr->ticket.data, outcr->ticket.length,
                         &enc_tkt, &out_len);
      if (rc) {
        print_krb5_error(ctx, stderr, "Internal error (Cannot parse encrypted ticket)", NULL, rc);
        goto cleanup;
      }
      princ_to_check->kdc_vno = enc_tkt.enc_part.kvno ? 
         *enc_tkt.enc_part.kvno : 0;
   }
      
  princ_to_check->est_lifetime = ticket->ticket.endtime - 
    ticket->ticket.authtime;
#endif
  /* minimum of 24 hours */
  if (princ_to_check->est_lifetime < 86400)
    princ_to_check->est_lifetime = 86400;
  ret=0;
 cleanup:
  if (ticket)
    krb5_free_ticket(ctx, ticket);
  if (srv_actx)
    krb5_auth_con_free(ctx, srv_actx);
  krb5_free_data_contents(ctx, &authent);
  if (outcr)
    krb5_free_creds(ctx, outcr);
  krb5_free_cred_contents(ctx, &cr);
  if (cli_actx)
    krb5_auth_con_free(ctx, cli_actx);
  if (cc)
    krb5_cc_close(ctx, cc);
  return ret;
}

void do_free_principals(krb5_context ctx, principal *princ_list) {
  principal *next;
  for (;princ_list;princ_list=next) {
    next=princ_list->next;
    krb5_free_principal(ctx, princ_list->name);
#if HAVE_DECL_KRB5_FREE_UNPARSED_NAME
    krb5_free_unparsed_name(ctx, princ_list->print_name);
#else
    krb5_xfree(princ_list->print_name);
#endif
    free(princ_list);
  }
}

krb5_keytab get_keytab(krb5_context ctx, char *keytab) 
{
  krb5_keytab kt=NULL;
  char *ktdef=NULL, *ktname=NULL;
  int rc;

  if (!keytab) {
    ktdef=malloc(BUFSIZ);
    if (!ktdef) {
      fprintf(stderr, "Memory allocation failed: %s", strerror(errno));
      goto out;
    } 
    rc = krb5_kt_default_name(ctx, ktdef, BUFSIZ);
    if (rc) {
      print_krb5_error(ctx, stderr, "Looking up default keytab name failed", NULL, rc);
      goto out;
    }   
    keytab = ktdef;
  }
  
  if (!strncmp(keytab, "FILE:", 5))
    keytab=&keytab[5];
  if (!strchr(keytab, ':')) {
    ktname = malloc(8 + strlen(keytab));
    if (!ktname) {
      fprintf(stderr, "Memory allocation failed: %s", strerror(errno));
      goto out;
    } 
    sprintf(ktname, "WRFILE:%s", keytab);
    rc = krb5_kt_resolve(ctx, ktname, &kt);
    if (rc) {
      sprintf(ktname, "FILE:%s", keytab);
      rc = krb5_kt_resolve(ctx, ktname, &kt);
      if (rc) {
	print_krb5_error(ctx, stderr, "Cannot open default keytab", NULL, rc);
	goto out;
      }
    } 
  } else {
    rc = krb5_kt_resolve(ctx, keytab, &kt);
    if (rc) {
      print_krb5_error(ctx, stderr, "Cannot open keytab", NULL, rc);
      goto out;
    }
  }
 out:
  if (ktdef)
    free(ktdef);
  if (ktname)
    free(ktname);
  return kt;
}

int main(int argc, char **argv) {
  krb5_context krb5_ctx;
  principal *keytab_princ_list=NULL, *tmp;
  krb5_error_code rc;
  krb5_keytab krb5_kt;

  if (krb5_init_context(&krb5_ctx)) {
    fprintf(stderr, "Cannot initialize krb5 library\n");
    exit(1);
  }

  krb5_kt = get_keytab(krb5_ctx, argc > 1 ? argv[1] : NULL);
  if (!krb5_kt) {
    exit(1);
  }

  enumerate_keytab(krb5_ctx, krb5_kt, &keytab_princ_list);
  for (tmp=keytab_princ_list; tmp;tmp=tmp->next) {
    if (tmp->mult_vno) {
      if (get_correct_vno(krb5_ctx, krb5_kt, tmp))
	continue;
      if (tmp->kdc_vno > tmp->min_vno &&
	  tmp->max_timestamp < time(0) - tmp->est_lifetime) {
	int vno, etype;
	krb5_keytab_entry rm_entry;
	memset(&rm_entry, 0, sizeof(krb5_keytab_entry));
	rm_entry.principal = tmp->name;
	rc = 0;
	for (vno=tmp->min_vno; vno < tmp->kdc_vno; vno++) {
	  rm_entry.vno = vno;
	  for (etype=tmp->min_enctype; etype <= tmp->max_enctype; etype++) {
	    Z_enctype(kte_keyblock(&rm_entry)) = etype;
#if 0
	    printf("Removing %s %d %d\n", tmp->print_name, vno, etype);
#else
	    rc = krb5_kt_remove_entry(krb5_ctx, krb5_kt, &rm_entry);
	    if (rc && rc != KRB5_KT_NOTFOUND) {
	      print_krb5_error(krb5_ctx, stderr, "Cannot remove keytab entry", tmp, rc);
	      break;
	    }
            rc = 0;
#endif
          }
          if (rc) break;
	}
      }
    }
  }
  krb5_kt_close(krb5_ctx, krb5_kt);
  do_free_principals(krb5_ctx, keytab_princ_list);
  keytab_princ_list=NULL;
  krb5_free_context(krb5_ctx);
  return 0;
}
