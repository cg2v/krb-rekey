AUTOMAKE_OPTIONS=foreign 1.9
bin_PROGRAMS=rekeymgr
sbin_PROGRAMS=$(SERVER_PROG) getnewkeys age_keytab
noinst_PROGRAMS=rekeytest
EXTRA_PROGRAMS=rekeysrv
EXTRA_DIST=dhp1024.pem  dhp2048.pem  dhp3072.pem  dhp4096.pem  dhp512.pem \
   dhp7680.pem m4/gnulib-cache.m4 sqlembed.pl rekey.sql SMakefile
BUILT_SOURCES=sqlinit.h dhp512.h dhp3072.h
CLEANFILES = sqlinit.h dhp512.h dhp3072.h
CLIENT_SOURCES=cltlib.c rekeylib.c memmgt.c memmgt.h  protocol.h  rekeyclt-locl.h  rekey-locl.h krb5_portability.h
rekeymgr_SOURCES=rekeyclt.c $(CLIENT_SOURCES)
rekeymgr_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5) $(LIB_COM_ERR) $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB)
getnewkeys_SOURCES=getnewkeys.c $(CLIENT_SOURCES)
getnewkeys_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5) $(LIB_COM_ERR) $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB)
rekeytest_SOURCES=rekeytest.c $(CLIENT_SOURCES)
rekeytest_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5)  $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB)
rekeysrv_SOURCES=srvmain.c srvnet.c srvops.c srvutil.c rekeylib.c memmgt.c memmgt.h  protocol.h rekey-locl.h  rekeysrv-locl.h sqlinit.h dhp512.h dhp3072.h
rekeysrv_LDADD=$(LDADD) $(LIB_GSS) $(LIB_SSL) $(LIB_KADMS) $(LIB_KRB5) $(LIB_SQLITE3) $(LIB_GROUPS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB) $(INET_NTOP_LIB)
age_keytab_SOURCES=age_keytab.c krb5_portability.h
age_keytab_LDADD=$(LDADD) $(LIB_KRB5)

%.h: %.pem
	openssl dhparam -C -noout -in $< | sed 's/^DH \*get_dh/static DH *get_dh/' > $@
sqlinit.h: $(srcdir)/sqlembed.pl $(srcdir)/rekey.sql
	perl $(srcdir)/sqlembed.pl < $(srcdir)/rekey.sql > $@
SUBDIRS=lib
ACLOCAL_AMFLAGS=-I m4
AM_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib $(KRB_INC_FLAGS)
LDADD = lib/libgnu.a

