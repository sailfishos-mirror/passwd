bin_PROGRAMS = passwd
man1_MANS = passwd.1
noinst_PROGRAMS = chfn chsh pwdstat
noinst_MANS = chfn.1 chsh.1
noinst_LIBRARIES = libstuff.a
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

chfn_SOURCES = \
	chfn.c

chsh_SOURCES = \
	chsh.c

passwd_SOURCES = \
	passwd.c

pwdstat_SOURCES = \
	pwdstat.c
