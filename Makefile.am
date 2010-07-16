SUBDIRS = po man
ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = passwd
noinst_PROGRAMS = pwdstat
noinst_LIBRARIES = libstuff.a
EXTRA_DIST = config.rpath mkinstalldirs m4/ChangeLog passwd.pamd passwd.spec.in passwd.spec
libstuff_a_SOURCES = pwdb.h

AM_CFLAGS = @LIBUSER_CFLAGS@
LDADD = libstuff.a @LIBUSER_LIBS@ @LIBS@

if USE_LIBUSER
libstuff_a_SOURCES += libuser.c
else
libstuff_a_SOURCES += pwdb.c
endif

if USE_SELINUX
libstuff_a_SOURCES += selinux_utils.c selinux_utils.h
endif

passwd_SOURCES = \
	passwd.c

pwdstat_SOURCES = \
	pwdstat.c
