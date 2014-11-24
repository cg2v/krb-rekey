AUTOMAKE_OPTIONS=foreign 1.9
bin_PROGRAMS=rekeymgr
sbin_PROGRAMS=$(SERVER_PROG) getnewkeys age_keytab
noinst_PROGRAMS=rekeytest
man_MANS=rekeymgr.1 age_keytab.8 getnewkeys.8 rekeysrv.8
EXTRA_PROGRAMS=rekeysrv try_acl
EXTRA_DIST=dhp1024.pem  dhp2048.pem  dhp3072.pem  dhp4096.pem  dhp512.pem \
   dhp7680.pem m4/gnulib-cache.m4 sqlembed.pl rekey.sql SMakefile
BUILT_SOURCES=sqlinit.h dhp7680.h
CLEANFILES = sqlinit.h dhp7680.h
CLIENT_SOURCES=cltlib.c rekeylib.c memmgt.c memmgt.h  protocol.h  rekeyclt-locl.h  rekey-locl.h krb5_portability.h
rekeymgr_SOURCES=rekeyclt.c $(CLIENT_SOURCES)
rekeymgr_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5) $(LIB_COM_ERR) $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB) $(LIBSOCKET)
getnewkeys_SOURCES=getnewkeys.c $(CLIENT_SOURCES)
getnewkeys_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5) $(LIB_COM_ERR) $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB) $(LIBSOCKET)
rekeytest_SOURCES=rekeytest.c $(CLIENT_SOURCES)
rekeytest_LDADD=$(LDADD) $(LIB_GSS) $(LIB_KRB5)  $(LIB_SSL) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB) $(LIBSOCKET)
rekeysrv_SOURCES=srvmain.c srvnet.c srvops.c acl.c srvutil.c rekeylib.c memmgt.c memmgt.h  protocol.h rekey-locl.h  rekeysrv-locl.h sqlinit.h dhp7680.h
EXTRA_rekeysrv_SOURCES=admin_ldapgroups.c admin_file.c
rekeysrv_LDADD=$(LDADD) admin_$(ADMIN_METHOD).$(OBJEXT) $(LIB_GSS) $(LIB_SSL) $(LIB_KADMS) $(LIB_KRB5) $(LIB_SQLITE3) $(LIB_GROUPS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(SERVENT_LIB) $(INET_NTOP_LIB) $(LIBSOCKET)
age_keytab_SOURCES=age_keytab.c krb5_portability.h
age_keytab_LDADD=$(LDADD) $(LIB_KRB5)
try_acl_SOURCES=try_acl.c acl.c rekeylib.c memmgt.c memmgt.h rekey-locl.h rekeysrv-locl.h
try_acl_LDADD=$(LDADD) $(LIB_GSS) $(LIB_SSL) $(LIB_KRB5)

%.h: %.pem
	openssl dhparam -C -noout -in $< | sed 's/^DH \*get_dh/static DH *get_dh/' > $@
sqlinit.h: $(srcdir)/sqlembed.pl $(srcdir)/rekey.sql
	perl $(srcdir)/sqlembed.pl < $(srcdir)/rekey.sql > $@
SUBDIRS=lib
ACLOCAL_AMFLAGS=-I m4
AM_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib $(KRB_INC_FLAGS) \
              -DSYSCONFDIR='"$(sysconfdir)"'
LDADD = lib/libgnu.a

KEEP_MAN_SECTS=ADMIN-$(ADMIN_METHOD)
sub_drs = s%\(\\f(CW\)*\@def_rekey_service\(\\fR\)*\@%$(def_rekey_service)%
sub_etc = s%\(\\f(CI\)*\@sysconfdir\(\\fI\)*\@%$(sysconfdir)%
keep_sect = /<<<===SECT-\($(KEEP_MAN_SECTS)\)===>>>/,/<<<===SECT-.*===>>>/p
cut_sect = /<<<===SECT-.*===>>>/,/<<<===SECT-ZZZ===>>>/d
#keep_sect = /<<<===KEEP-\($(KEEP_MAN_SECTS)\)===>>>/,/<<<===END-KEEP===>>>/p
#cut_sect = /<<<===BEGIN-CUT===>>>/,/<<<===END-CUT===>>>/d
man_sed_prog = '$(sub_drs);$(sub_etc);$(keep_sect);$(cut_sect)'

rekeymgr.1: rekeymgr.1.in
	sed $(man_sed_prog) < $< > $@
rekeysrv.8: rekeysrv.8.in
	sed $(man_sed_prog) < $< > $@
getnewkeys.8: getnewkeys.8.in
	sed $(man_sed_prog) < $< > $@
