bin_PROGRAMS = passwd
man1_MANS = passwd.1
noinst_PROGRAMS = pwdstat
noinst_LIBRARIES = libstuff.a
EXTRA_DIST = passwd.pamd passwd.1 passwd.spec.in passwd.spec
libstuff_a_SOURCES = \
	date.h \
	pwdb.h \
	version.c \
	version.h 

date.h:
	echo 'static const char *version_date = "' `date +%D` '";' > date.h

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

passwd.spec: passwd.spec.in configure.ac
	./autogen.sh
