AC_INIT(passwd, 0.77)
AC_CONFIG_SRCDIR([configure.ac])
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])

AC_PROG_CC
AC_PROG_RANLIB

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup])

AC_ARG_WITH(pwdb,
AS_HELP_STRING([--with-pwdb],[usepwdb for modifying user accounts]),
use_pwdb=$withval,
use_pwdb=no)

AC_ARG_WITH(libuser,
AS_HELP_STRING([--without-libuser],[don't use libuser for modifying user accounts]),
use_libuser=$withval,
use_libuser=no)

if test x$use_pwdb = xno -a x$use_libuser = xno ; then
	use_libuser=yes
fi

if test x$use_libuser != xno ; then
	PKG_CHECK_MODULES(LIBUSER,libuser)
	AC_DEFINE(LIBUSER,1,[Define if you wish to use libuser.])
else
	if test x$use_pwdb != xno ; then
		AC_DEFINE(PWDB,1,[Define if you wish to use pwdb.])
		if "$use_pwdb" != "yes" ; then
			if "$use_pwdb" != "/usr" ; then
				CFLAGS="$CFLAGS -I$use_pwdb/include"
				LIBS="$LIBS -L$use_pwdb/lib"
			fi
		fi
	fi
fi

AC_ARG_WITH(selinux,
AS_HELP_STRING([--with-selinux],[use SELinux]),
use_selinux=$withval,
use_selinux=auto)
if test x$use_selinux != xno ; then
	AC_CHECK_FUNC(security_compute_av,,
		      [AC_CHECK_LIB(selinux,security_compute_av)])
	if test x$ac_cv_lib_selinux_security_compute_av != xyes ; then
		if test x$use_selinux != xauto ; then
			AC_MSG_ERROR([requested SELinux, but libselinux was not found])
		fi
		use_selinux=no
	else
		AC_DEFINE(WITH_SELINUX,1,[Define if you want to use SELinux.])
	fi
fi

AC_ARG_WITH(audit,
AS_HELP_STRING([--with-audit],[log using Linux Audit in addition to syslog]),
use_audit=$withval,
use_audit=auto)
if test x$use_audit != xno ; then
	AC_CHECK_FUNC(audit_open,,
		      [AC_CHECK_LIB(audit,audit_open)])
	if test x$ac_cv_lib_audit_audit_open != xyes ; then
		if test x$use_audit != xauto ; then
			AC_MSG_ERROR([requested Linux Audit, but libaudit was not found])
		fi
	else
		AC_DEFINE(WITH_AUDIT,1,[Define if you want to use Linux Audit.])
	fi
fi

AC_DEFINE(_GNU_SOURCE,1,[Define if you want to use GNU extensions.])

AM_MAINTAINER_MODE

AM_CONDITIONAL(USE_SELINUX,test x$use_selinux != xno)
AM_CONDITIONAL(USE_AUDIT,test x$use_audit != xno)
AM_CONDITIONAL(USE_LIBUSER,test x$use_libuser != xno)

AC_CHECK_FUNC(dlopen,,[AC_CHECK_LIB(dl,dlopen)])
AC_CHECK_FUNC(misc_conv,,[AC_CHECK_LIB(pam_misc,misc_conv)])
AC_CHECK_FUNC(pam_authenticate,,[AC_CHECK_LIB(pam,pam_authenticate)])
AC_CHECK_FUNC(poptGetContext,,[AC_CHECK_LIB(popt,poptGetContext)])

if test x$GCC = xyes ; then
	WARNINGS="-Waggregate-return -Wcast-align -Wimplicit -Wmissing-declarations -Wmissing-prototypes -Wpointer-arith -Wstrict-prototypes -Wuninitialized -Wsign-compare -Wunused-value"
	CFLAGS="$CFLAGS $WARNINGS"
fi

AM_GNU_GETTEXT_VERSION
AM_GNU_GETTEXT([external])
AC_CHECK_FUNCS(dngettext)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
