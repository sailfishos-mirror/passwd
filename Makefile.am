## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = @LIBUSER_CFLAGS@ -fpie
AM_LDFLAGS = -pie -Wl,-z,relro,-z,now

## Targets
SUBDIRS = man/ja po

bin_PROGRAMS = passwd
dist_man_MANS = man/passwd.1
noinst_PROGRAMS = pwdstat

noinst_LIBRARIES = libstuff.a

## Rules
EXTRA_DIST = passwd.pamd

libstuff_a_SOURCES = pwdb.h

if USE_LIBUSER
libstuff_a_SOURCES += libuser.c
else
libstuff_a_SOURCES += pwdb.c
endif

if USE_SELINUX
libstuff_a_SOURCES += selinux_utils.c selinux_utils.h
endif

passwd_LDADD = libstuff.a $(LIBUSER_LIBS)
