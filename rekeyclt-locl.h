#ifndef _CLT_LOCL_H
#define _CLT_LOCL_H

void ssl_startup(void);
void ssl_cleanup(void);
int sendrcv(SSL *, int, mb_t);
SSL *c_connect(char *);
void c_auth(SSL *, char *);
void c_newreq(SSL *, char *, int, int, char **);
void c_status(SSL *, char *);
void c_getkeys(SSL *);

#endif
