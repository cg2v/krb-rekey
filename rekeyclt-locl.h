#ifndef _CLT_LOCL_H
#define _CLT_LOCL_H

void ssl_startup(void);
void ssl_cleanup(void);
char *get_server(char *);
int get_keytab_targets(char *, int *, char ***);
int sendrcv(SSL *, int, mb_t);
SSL *c_connect(char *);
void c_auth(SSL *, char *, char *);
void c_newreq(SSL *, char *, int, int, char **);
void c_status(SSL *, char *);
void c_finalize(SSL *, char *);
void c_delprinc(SSL *, char *);
void c_simplekey(SSL *, char *, int, char *);
void c_getkeys(SSL *, char *, int, char **);
void c_abort(SSL *ssl, char *);
void c_close(SSL *ssl);
#endif
