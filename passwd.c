/*
 * Copyright Red Hat, Inc., 1998, 1999, 2001, 2002.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Written by Cristian Gafton <gafton@redhat.com> */

#ident "$Id$"

#include "config.h"

#include <sys/types.h>

#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <popt.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "pwdb.h"

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/av_permissions.h>
#include "selinux_utils.h"
#endif

#define _(String) String
#define N_(String) String

#ifdef HAVE_LIBLAUS

#include <stdarg.h>
#include <laus.h>
static int __laus_active;

#endif

/* conversation function & corresponding structure */
static struct pam_conv conv = {
	misc_conv,
	NULL
};

const char *username = NULL;	/* username specified on the command line */
const char *progname = NULL;	/* the name of the program */
int passwd_flags = 0;		/* flags specified by root */

#define PASSWD_KEEP	0x0001	/* keep un-expired tokens */

#define PASSWD_LOCK	0x0002	/* lock the password */
#define PASSWD_UNLOCK	0x0004	/* unlock the password, if locked */
#define PASSWD_DELETE	0x0008	/* delete the user's password */
#define PASSWD_STATUS	0x0010	/* report the password status */
#define PASSWD_FORCE	0x0020	/* force change of expired token */
#define PASSWD_STDIN	0x0040	/* read the password from stdin (root only) */
#define PASSWD_ROOT	0x001E	/* options which are mutually exclusive */

#define PASSWD_MIN	0x0100	/* set the minimum password lifetime */
#define PASSWD_MAX	0x0200	/* set the maximum password lifetime */
#define PASSWD_WARN	0x0400	/* set the password warning */
#define PASSWD_INACT	0x0800	/* set the inactive time */
#define PASSWD_AGING	0x0F00	/* aging options */

#ifdef HAVE_PAM_FAIL_DELAY
#define PASSWD_FAIL_DELAY	2000000	/* usec delay on failure */
#endif


/*
 *  laus helper functions
 *  contents conditionally compiled
 */
static void
laus_help_errmsg(const char *f, int x)
{
#ifdef HAVE_LIBLAUS
	if (!__laus_active) {
		return;
	}
	syslog(LOG_WARNING,
	       "LAuS error - %s:%i - %s: (%i) %s\n",
	       __FILE__, __LINE__,
	       f, x, laus_strerror(x));
#endif
}

static void
laus_help_log(const char *tag, const char *fmt, ...)
{
#ifdef HAVE_LIBLAUS
	char buffer[8*1024] = {0};
	va_list arg_list;

	if (!__laus_active) {
		return;
	}

	va_start(arg_list, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, arg_list);
	va_end(arg_list);

	if (laus_log(tag, "%s", buffer) < 0 ) {
		laus_help_errmsg("laus_log", errno);
	}
#endif
}

static void
laus_help_open(void)
{
#ifdef HAVE_LIBLAUS
	if (laus_open(NULL) < 0) {
		laus_help_errmsg("laus_open", errno);
		__laus_active = 0;
	} else {
		__laus_active = 1;
	}
#endif
}


/* A conversation function which uses an internally-stored value for
 * the responses. */
static int
stdin_conv(int num_msg, const struct pam_message **msgm,
	   struct pam_response **response, void *appdata_ptr)
{
	struct pam_response *reply;
	int count;

	/* Sanity test. */
	if (num_msg <= 0) {
		return PAM_CONV_ERR;
	}

	/* Allocate memory for the responses. */
	reply = calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		return PAM_CONV_ERR;
	}

	/* Each prompt elicits the same response. */
	for (count = 0; count < num_msg; ++count) {
		reply[count].resp_retcode = 0;
		reply[count].resp = strdup(appdata_ptr);
	}

	/* Set the pointers in the response structure and return. */
	*response = reply;
	return PAM_SUCCESS;
}

/* Parse command-line arguments, rejecting conflicting flags and performing
 * various other initialization tasks. */
static void
parse_args(int argc, const char **argv,
	   long *min, long *max, long *warn, long *inact)
{
	poptContext optCon;
	int delete = 0, force = 0, keep = 0, lock = 0, status = 0, unlock = 0;
	int use_stdin = 0;
	int rc;
	const char **extraArgs;
	struct poptOption options[] = {
		{"keep-tokens", 'k', POPT_ARG_NONE, &keep, 0,
		 "keep non-expired authentication tokens"},
		{"delete", 'd', POPT_ARG_NONE, &delete, 0,
		 "delete the password for the named account (root only)"},
		{"lock", 'l', POPT_ARG_NONE, &lock, 0,
		 "lock the named account (root only)"},
		{"unlock", 'u', POPT_ARG_NONE, &unlock, 0,
		 "unlock the named account (root only)"},
		{"force", 'f', POPT_ARG_NONE, &force, 0,
		 "force operation\n"},
		{"maximum", 'x', POPT_ARG_LONG, max, 0,
		 "maximum password lifetime (root only)", "DAYS"},
		{"minimum", 'n', POPT_ARG_LONG, min, 0,
		 "minimum password lifetime (root only)", "DAYS"},
		{"warning", 'w', POPT_ARG_LONG, warn, 0,
		 "number of days warning users receives before password "
		 "expiration (root only)", "DAYS"},
		{"inactive", 'i', POPT_ARG_LONG, inact, 0,
		 "number of days after password expiration when an account "
		 "becomes disabled (root only)", "DAYS"},
		{"status", 'S', POPT_ARG_NONE, &status, 0,
		 "report password status on the named account (root only)"},
		{"stdin", '\0', POPT_ARG_NONE, &use_stdin, 0,
		 "read new tokens from stdin (root only)"},
		POPT_AUTOHELP {NULL, '\0', 0, NULL},
	};
	struct passwd *pw;

	*min = *max = *warn = *inact = -2;
	optCon = poptGetContext("passwd", argc, argv, options, 0);
	poptSetOtherOptionHelp(optCon, "[OPTION...] <accountName>");

	if ((rc = poptGetNextOpt(optCon)) < -1) {
		fprintf(stderr, _("%s: bad argument %s: %s\n"), progname,
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(rc));
		exit(-3);
	}

	extraArgs = poptGetArgs(optCon);

	if (keep) {
		passwd_flags |= PASSWD_KEEP;
	}
	if (lock) {
		passwd_flags |= PASSWD_LOCK;
	}
	if (unlock) {
		passwd_flags |= PASSWD_UNLOCK;
	}
	if (status) {
		passwd_flags |= PASSWD_STATUS;
	}
	if (delete) {
		passwd_flags |= PASSWD_DELETE;
	}
	if (force) {
		passwd_flags |= PASSWD_FORCE;
	}
	if (use_stdin) {
		passwd_flags |= PASSWD_STDIN;
	}
	if (*min != -2) {
		passwd_flags |= PASSWD_MIN;
	}
	if (*max != -2) {
		passwd_flags |= PASSWD_MAX;
	}
	if (*warn != -2) {
		passwd_flags |= PASSWD_WARN;
	}
	if (*inact != -2) {
		passwd_flags |= PASSWD_INACT;
	}

	/* The rest of the flags are mutually-exclusive, except for --force. */
	if (passwd_flags) {
		int tmp;
		int count;
		tmp = passwd_flags & PASSWD_ROOT;
		count = 0;
		/* Check the rightmost bit and shift right. */
		while (tmp != 0) {
			if (tmp & 0x01) {
				count++;
			}
			tmp = tmp >> 1;
		}
		/* Error if other bits are set. */
		if (count > 1) {
			fprintf(stderr,
				_("%s: Only one of -l, -u, -d, -S may be specified.\n"),
				progname);
			exit(-2);
		}
		/* Error out if we had -l/-u/-d/-S and an aging option. */
		if (count > 0) {
			tmp = passwd_flags & PASSWD_AGING;
			if (tmp != 0) {
				fprintf(stderr,
					_("%s: Cannot mix one of -l, -u, -d, -S and one of -i, -n, -w, -x.\n"),
					progname);
				exit(-2);
			}
		}
	}

	/* The only flag which unprivileged users get to use is -k. */
	if ((passwd_flags & ~PASSWD_KEEP) && (getuid() != 0)) {
		if (passwd_flags & PASSWD_STATUS) {
			laus_help_log(NO_TAG, "passwd: password status display for all users denied - by=%u",
				      getuid());
		} else {
			laus_help_log(NO_TAG, "passwd: password attribute change denied - by=%u",
				      getuid());
		}
		fprintf(stderr, _("Only root can do that.\n"));
		exit(-2);
	}

	/* Only root gets to specify a user name. */
	username = NULL;
	if ((extraArgs != NULL) && (extraArgs[0] != NULL)) {
		if (getuid() != 0) {
			/* The invoking user was not root. */
			laus_help_log(NO_TAG, "passwd: password change denied - user=%s, by=%u",
				      extraArgs[0], getuid());
			fprintf(stderr,
				_("%s: Only root can specify a user name.\n"),
				progname);
			exit(-3);
		} else {
			/* The invoking user was root. */
			username = extraArgs[0];
			/* Sanity-check the user name */
			if (strlen(username) > MAX_USERNAMESIZE) {
				fprintf(stderr,
					_("%s: The user name supplied is too long.\n"),
					progname);
				exit(-3);
			}
		}

		/* If there is more than one unrecognized argument, we suddenly
		 * get confused. */
		if (extraArgs[1] != NULL) {
			fprintf(stderr,
				_("%s: Only one user name may be specified.\n"),
				progname);
			exit(-3);
		}
	}

	/* Now if any of the -l, -u, -d, -S, -i, -n, -w, or -x options were
	 * given, and a username was not specified, bail out. */
	if ((passwd_flags & ~PASSWD_KEEP) && (username == NULL)) {
		fprintf(stderr,
			_("%s: This option requires a user name.\n"),
			progname);
		exit(-2);
	}

	/* Determine the name of the user whose account we're operating on,
	 * and make sure the account exists. */
	if (username == NULL) {
		/* The invoking user. */
		pw = getpwuid(getuid());
		if (pw == NULL) {
			fprintf(stderr, _("%s: Can not identify you!\n"),
				progname);
			exit(-3);
		}
		username = strdup(pw->pw_name);
	} else {
		/* The name specified on the command-line. */
		pw = getpwnam(username);
		if (pw == NULL) {
			fprintf(stderr, _("%s: Unknown user name '%s'.\n"),
				progname, username);
			exit(-4);
		}
	}
}

int
main(int argc, const char **argv)
{
	int retval;
	long min, max, warn, inact;
	pam_handle_t *pamh = NULL;
	struct passwd *pwd;

	laus_help_open();

	/* Parse command-line arguments. */
	progname = basename(argv[0]);
	parse_args(argc, argv, &min, &max, &warn, &inact);

	pwd = getpwnam(username);
	if (pwd == NULL) {
		fprintf(stderr, _("%s: Unknown user name '%s'.\n"),
			progname, username);
		exit(-4);
	}

#ifdef WITH_SELINUX
	if ((is_selinux_enabled() > 0) &&
	    (getuid() == 0) &&
	    (check_selinux_access(username, PASSWD__PASSWD) != 0)) {
		security_context_t user_context;
		if (getprevcon(&user_context) < 0) {
			user_context = strdup(_("Unknown user context"));
		}
		syslog(LOG_ALERT,
		       _("%s is not authorized to change the password of %s\n"),
		       user_context, username);
		fprintf(stderr,
			_("%s: %s is not authorized to change the "
			  "password of %s\n"),
			progname, user_context, username);
		freecon(user_context);
		exit(1);
	}
#endif

	/* Handle account locking request. */
	if (passwd_flags & PASSWD_LOCK) {
		printf(_("Locking password for user %s.\n"), username);
		retval = pwdb_lock_password(username);
		printf("%s: %s\n", progname,
		       retval ==
		       0 ? "Success" : "Error (password not set?)");
		if (retval == 0) {
			laus_help_log(NO_TAG, "passwd: password locked "
				      "- user=%s, uid=%u, id=%u",
				      username, pwd->pw_uid, getuid());
		}
		return retval;
	}
	/* Handle account unlocking request. */
	if (passwd_flags & PASSWD_UNLOCK) {
		printf(_("Unlocking password for user %s.\n"), username);
		retval = pwdb_unlock_password(username,
					      passwd_flags & PASSWD_FORCE);
		printf("%s: %s\n", progname,
		       retval == 0 ? _("Success.") :
		       retval ==
		       -2 ? _("Unsafe operation (use -f to force).") :
		       _("Error (password not set?)"));
		if (retval == 0) {
			laus_help_log(NO_TAG, "passwd: password unlocked "
				      "-user=%s, uid=%u, id=%u",
				      username, pwd->pw_uid, getuid());
		}
		return retval;
	}
	/* Handle password clearing request. */
	if (passwd_flags & PASSWD_DELETE) {
		printf(_("Removing password for user %s.\n"), username);
		retval = pwdb_clear_password(username);
		printf("%s: %s\n", progname,
		       (retval == 0) ? _("Success") : _("Error"));
		if (retval == 0) {
			laus_help_log(NO_TAG, "passwd: password deleted "
				      "-user=%s, uid=%u, id=%u",
				      username, pwd->pw_uid, getuid());
		}
		return retval;
	}
	/* Display account status. */
	if (passwd_flags & PASSWD_STATUS) {
		retval = pwdb_display_status(username);
		if (retval == 0) {
		laus_help_log(NO_TAG, "passwd: password status displayed for "
			      "all users - by=%u", getuid());
		}
		return retval;
	}
	/* Adjust aging parameters. */
	if (passwd_flags & PASSWD_AGING) {
		printf(_("Adjusting aging data for user %s.\n"), username);
		retval = pwdb_update_aging(username, min, max, warn, inact);
		printf("%s: %s\n", progname,
		       (retval == 0) ? _("Success") : _("Error"));
		if (retval == 0) {
			laus_help_log(NO_TAG, "passwd: password aging data "
				      "updated - user=%s, uid=%u, min=%li, "
				      "max=%li, warn=%li, inact=%li, by=%u",
			username, pwd->pw_uid, min, max, warn, inact, getuid());
		}
		return retval;
	}

	/* The standard behavior follows.  At this point we know for whom
	 * we are going to change a password, so let the invoking user
	 * know what's going on. */
	printf(_("Changing password for user %s.\n"), username);

	/* If we need to read the new password from stdin, read it and switch
	 * to the really-quiet stdin conversation function. */
	if (passwd_flags & PASSWD_STDIN) {
		char newPassword[80];
		int i;

		i = read(STDIN_FILENO, newPassword,
			 sizeof(newPassword) - 1);
		newPassword[i - 1] = '\0';
		conv.conv = stdin_conv;
		conv.appdata_ptr = strdup(newPassword);
	}

	/* Start up PAM. */
	retval = pam_start("passwd", username, &conv, &pamh);

#ifdef HAVE_PAM_FAIL_DELAY
	/* We have to pause on failure, so tell libpam the minimum amount
	 * of time it should wait after a failure. */
	retval = pam_fail_delay(pamh, PASSWD_FAIL_DELAY);
	if (retval != PAM_SUCCESS) {
		fprintf(stderr, _("passwd: unable to set failure delay\n"));
		exit(1);
	}
#endif

	/* Go for it. */
	retval = pam_chauthtok(pamh,
			       (passwd_flags & PASSWD_KEEP) ?
			       PAM_CHANGE_EXPIRED_AUTHTOK : 0);
	if (retval == PAM_SUCCESS) {
		/* We're done.  Tell the invoking user that it worked. */
		retval = pam_end(pamh, PAM_SUCCESS);
		if (passwd_flags & PASSWD_KEEP) {
			laus_help_log(NO_TAG, "passwd: password changed - user=%s, uid=%u, by=%u",
				      username, pwd->pw_uid, getuid());
			printf(_("passwd: expired authentication tokens updated successfully.\n"));
		} else {
			laus_help_log(NO_TAG, "passwd: password changed - user=%s, uid=%u, by=%u",
				      username, pwd->pw_uid, getuid());
			printf(_("passwd: all authentication tokens updated successfully.\n"));
		}
		retval = 0;
	} else {
		/* Horrors!  It failed.  Relay the bad news. */
		laus_help_log(NO_TAG, "passwd: password change failed - user=%s, uid=%u, by=%u",
			      username, pwd->pw_uid, getuid());
		fprintf(stderr, _("passwd: %s\n"),
			pam_strerror(pamh, retval));
		pam_end(pamh, retval);
		retval = 1;
	}
	return retval;
}
