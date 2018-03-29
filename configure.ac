# Process this file with autoconf to produce a configure script.
AC_INIT([passwd], [0.80])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([admin])
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip no-define -Wall])

# Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# Checks for libraries.
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
else
	if test x$use_pwdb != xno ; then
		if "$use_pwdb" != "yes" ; then
			if "$use_pwdb" != "/usr" ; then
				CFLAGS="$CFLAGS -I$use_pwdb/include"
				LIBS="$LIBS -L$use_pwdb/lib"
			fi
		fi
	fi
fi
AM_CONDITIONAL(USE_LIBUSER,test x$use_libuser != xno)

AC_ARG_WITH(selinux,
AS_HELP_STRING([--with-selinux],[use SELinux]),
use_selinux=$withval,
use_selinux=auto)
if test x$use_selinux != xno ; then
	AC_SEARCH_LIBS([security_compute_av], [selinux])
	if test x$ac_cv_search_security_compute_av = xno ; then
		if test x$use_selinux != xauto ; then
			AC_MSG_ERROR([requested SELinux, but libselinux was not found])
		fi
		use_selinux=no
	else
		AC_DEFINE(WITH_SELINUX,1,[Define if you want to use SELinux.])
	fi
fi
AM_CONDITIONAL(USE_SELINUX,test x$use_selinux != xno)

AC_ARG_WITH(audit,
AS_HELP_STRING([--with-audit],[log using Linux Audit in addition to syslog]),
use_audit=$withval,
use_audit=auto)
if test x$use_audit != xno ; then
	AC_SEARCH_LIBS([audit_open], [audit])
	if test x$ac_cv_search_audit_open = xno ; then
		if test x$use_audit != xauto ; then
			AC_MSG_ERROR([requested Linux Audit, but libaudit was not found])
		fi
	else
		AC_DEFINE(WITH_AUDIT,1,[Define if you want to use Linux Audit.])
	fi
fi

AC_SEARCH_LIBS([misc_conv], [pam_misc])
AC_SEARCH_LIBS([pam_authenticate], [pam])
AC_SEARCH_LIBS([poptGetContext], [popt])

AM_GNU_GETTEXT_VERSION([0.18.2])
AM_GNU_GETTEXT([external])

# Checks for header files.

# Checks for types.

# Checks for structures.

# Checks for compiler characteristics.

# Checks for library functions.
AC_FUNC_ALLOCA

# Checks for system services.

# Miscellanous hackery.

# Modify CFLAGS after all tests are run (some of them would fail because
# of the -Werror).
if test "$GCC" = yes ; then
    AC_CACHE_CHECK([for available GCC warning flags],
		   [mitr_cv_prog_gcc_warnings],
    [mitr_cv_prog_gcc_warnings=""
    for i in -Wall -W -Waggregate-return -Wcast-align -Wmissing-declarations dnl
 -Wmissing-noreturn -Wmissing-prototypes -Wpointer-arith -Wshadow dnl
 -Wstrict-prototypes -Wuninitialized -Wwrite-strings; do
        oldcflags=$CFLAGS
        CFLAGS="$CFLAGS $i"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
		[mitr_cv_prog_gcc_warnings="$mitr_cv_prog_gcc_warnings $i"])
	CFLAGS=$oldcflags
     done])
     CFLAGS="$CFLAGS $mitr_cv_prog_gcc_warnings"
     AC_MSG_CHECKING([whether we should use -Werror])
     AC_ARG_ENABLE([Werror],
		   AS_HELP_STRING([--enable-Werror],
			[use -Werror if compiling with gcc (default is NO)]),
		   [], enable_Werror=no)
     if test "x$enable_Werror" != xno; then
	CFLAGS="$CFLAGS -Werror"
     fi
     AC_MSG_RESULT([$enable_Werror])
fi

AC_CONFIG_FILES([Makefile man/ja/Makefile po/Makefile.in])
AC_OUTPUT
