AUTOMAKE_OPTIONS=foreign 1.9
bin_PROGRAMS=rekeyclt
sbin_PROGRAMS=rekeysrv
EXTRA_DIST=*.pem m4/gnulib-cache.m4
BUILT_SOURCES=sqlinit.c dhp512.c dhp3072.c
CLEANFILES = sqlinit.c dhp512.c dhp3072.c
rekeysrv_DEPENDENCIES=sqlinit.c dhp512.c dhp3072.c
rekeyclt_SOURCES=rekeyclt.c cltlib.c rekeylib.c memmgt.c
rekeyclt_LDADD=$(LDADD) @LIB_GSS@ @LIB_SSL@ 
rekeysrv_SOURCES=srvmain.c srvnet.c srvops.c srvutil.c rekeylib.c memmgt.c
rekeysrv_LDADD=$(LDADD) @LIB_GSS@ @LIB_SSL@ @LIB_KADMS@ @LIB_KRB5@ @LIB_SQLITE3@

%.c: %.pem
	openssl dhparam -C -noout -in $< | sed 's/^DH \*get_dh/static DH *get_dh/' > $@
sqlinit.c: sqlembed.pl rekey.sql
	perl sqlembed.pl < rekey.sql > $@
SUBDIRS=lib
ACLOCAL_AMFLAGS=-I m4
AM_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib $(KRB_INC_FLAGS)
LDADD = lib/libgnu.a

