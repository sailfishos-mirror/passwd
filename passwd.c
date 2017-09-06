/*
 * Copyright Red Hat, Inc., 1998, 1999, 2001, 2002, 2015.
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

#include "config.h"

#include <sys/types.h>

#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <popt.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <locale.h>
#include <libintl.h>
#include "pwdb.h"

#ifdef WITH_SELINUX
#include "selinux_utils.h"
#else
#define selinux_init(x) 0
#define selinux_check_root() 0
#endif

#ifdef WITH_AUDIT
#include <libaudit.h>
#else
#define audit_log_acct_message(d,ty,p,o,n,i,h,a,t,r) do { ; } while(0) 
static int audit_open(void) { errno = EPROTONOSUPPORT; return -1; } 
#endif

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static int audit_fd = -1;

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
#define PASSWD_EXPIRE	0x0080	/* expire the password */
#define PASSWD_ROOT	0x009E	/* options which are mutually exclusive */

#define PASSWD_MIN	0x0100	/* set the minimum password lifetime */
#define PASSWD_MAX	0x0200	/* set the maximum password lifetime */
#define PASSWD_WARN	0x0400	/* set the password warning */
#define PASSWD_INACT	0x0800	/* set the inactive time */
#define PASSWD_AGING	0x0F00	/* aging options */

#ifdef HAVE_PAM_FAIL_DELAY
#define PASSWD_FAIL_DELAY	2000000	/* usec delay on failure */
#endif


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
		if (msgm[count]->msg_style == PAM_PROMPT_ECHO_OFF) {
			reply[count].resp_retcode = 0;
			reply[count].resp = strdup(appdata_ptr);
		} else {
			reply[count].resp_retcode = 0;
			reply[count].resp = strdup("");
		}
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
	int expire = 0;
	int use_stdin = 0;
	int rc;
	const char **extraArgs;
	struct poptOption options[] = {
		{"keep-tokens", 'k', POPT_ARG_NONE, &keep, 0,
		 _("keep non-expired authentication tokens"), NULL},
		{"delete", 'd', POPT_ARG_NONE, &delete, 0,
		 _("delete the password for the named account (root only); "
		 "also removes password lock if any"), NULL},
		{"lock", 'l', POPT_ARG_NONE, &lock, 0,
		 _("lock the password for the named account (root only)"),
		 NULL},
		{"unlock", 'u', POPT_ARG_NONE, &unlock, 0,
		 _("unlock the password for the named account (root only)"),
		 NULL},
		{"expire", 'e', POPT_ARG_NONE, &expire, 0,
		 _("expire the password for the named account (root only)"),
		 NULL},
		{"force", 'f', POPT_ARG_NONE, &force, 0,
		 _("force operation"), NULL},
		{"maximum", 'x', POPT_ARG_LONG, max, 0,
		 _("maximum password lifetime (root only)"), "DAYS"},
		{"minimum", 'n', POPT_ARG_LONG, min, 0,
		 _("minimum password lifetime (root only)"), "DAYS"},
		{"warning", 'w', POPT_ARG_LONG, warn, 0,
		 _("number of days warning users receives before password "
		 "expiration (root only)"), "DAYS"},
		{"inactive", 'i', POPT_ARG_LONG, inact, 0,
		 _("number of days after password expiration when an account "
		 "becomes disabled (root only)"), "DAYS"},
		{"status", 'S', POPT_ARG_NONE, &status, 0,
		 _("report password status on the named account (root only)"),
		 NULL},
		{"stdin", '\0', POPT_ARG_NONE, &use_stdin, 0,
		 _("read new tokens from stdin (root only)"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};
	struct passwd *pw;

	*min = *max = *warn = *inact = -2;
	optCon = poptGetContext("passwd", argc, argv, options, 0);
	poptSetOtherOptionHelp(optCon, _("[OPTION...] <accountName>"));

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
	if (expire) {
		passwd_flags |= PASSWD_EXPIRE;
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
	if ((passwd_flags & ~PASSWD_KEEP) && 
	    (getuid() != 0)) {
		/* Auditing is not needed for displaying status */
		if (passwd_flags != PASSWD_STATUS) {
			audit_log_acct_message(audit_fd,  AUDIT_USER_CHAUTHTOK,
				NULL, "attempted-to-change-password-attribute",
				NULL, getuid(), NULL, NULL, NULL, 0);
		}
		fprintf(stderr, _("Only root can do that.\n"));
		exit(-2);
	}

	/* Only root gets to specify a user name. */
	username = NULL;
	if ((extraArgs != NULL) && (extraArgs[0] != NULL)) {
		if (getuid() != 0) {
			/* The invoking user was not root. */
			audit_log_acct_message(audit_fd,  AUDIT_USER_CHAUTHTOK,
				NULL, "attempted-to-change-password",
				extraArgs[0], getuid(), NULL, NULL, NULL, 0);
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
	char *tty_name, *ttyn;

	setlocale(LC_ALL, "");
	bindtextdomain("passwd", "/usr/share/locale");
	textdomain("passwd");
	
	audit_fd = audit_open();
	if (audit_fd < 0 && !(errno == EINVAL || errno == EPROTONOSUPPORT ||
				errno == EAFNOSUPPORT)) {
		/* The above error codes are only given when the kernel doesn't
		 * have audit compiled in. */
		fprintf(stderr, "Error - unable to connect to audit system\n");
		exit(1);
	}

	/* Parse command-line arguments. */
	progname = basename(argv[0]);
	parse_args(argc, argv, &min, &max, &warn, &inact);

	pwd = getpwnam(username);
	if (pwd == NULL) {
		fprintf(stderr, _("%s: Unknown user name '%s'.\n"),
			progname, username);
		exit(-4);
	}

	if (audit_fd >= 0)
		selinux_init(audit_fd);

	if (selinux_check_root() != 0) {
		fprintf(stderr, _("%s: SELinux denying access due to security policy.\n"), progname);
		
		audit_log_acct_message(audit_fd,  AUDIT_USER_CHAUTHTOK,
			NULL, "attempted-to-change-password", NULL, pwd->pw_uid,
			NULL, NULL, NULL, 0);
		exit(1);
	}

	/* Handle account locking request. */
	if (passwd_flags & PASSWD_LOCK) {
		printf(_("Locking password for user %s.\n"), username);
		retval = pwdb_lock_password(username);
		printf("%s: %s\n", progname,
		       retval ==
		       0 ? _("Success") : _("Error (password not set?)"));
		audit_log_acct_message(audit_fd, AUDIT_ACCT_LOCK,
			NULL, "locked-password", NULL, pwd->pw_uid,
			NULL, NULL, NULL, retval == 0);
		return retval;
	}
	/* Handle account unlocking request. */
	if (passwd_flags & PASSWD_UNLOCK) {
		printf(_("Unlocking password for user %s.\n"), username);
		retval = pwdb_unlock_password(username,
					      passwd_flags & PASSWD_FORCE);
		printf("%s: %s\n", progname,
		       retval == 0 ? _("Success") :
		       retval ==
		       -2 ? _("Unsafe operation (use -f to force)") :
		       _("Error (password not set?)"));
		audit_log_acct_message(audit_fd, AUDIT_ACCT_UNLOCK,
			NULL, "unlocked-password", NULL, pwd->pw_uid,
			NULL, NULL, NULL, retval == 0);
		return retval;
	}
	/* Handle password expiration request. */
	if (passwd_flags & PASSWD_EXPIRE) {
		printf(_("Expiring password for user %s.\n"), username);
		retval = pwdb_update_aging(username, -2, -2, -2, -2, 0);
		printf("%s: %s\n", progname,
		       retval ==
		       0 ? _("Success") : _("Error"));
		audit_log_acct_message(audit_fd, AUDIT_USER_MGMT,
			NULL, "expired-password", NULL, pwd->pw_uid,
			NULL, NULL, NULL, retval == 0);
		return retval;
	}
	/* Handle password clearing request. */
	if (passwd_flags & PASSWD_DELETE) {
		printf(_("Removing password for user %s.\n"), username);
		retval = pwdb_clear_password(username);
		printf("%s: %s\n", progname,
		       (retval == 0) ? _("Success") : _("Error"));
		audit_log_acct_message(audit_fd,  AUDIT_USER_CHAUTHTOK,
			NULL, "deleted-password", NULL, pwd->pw_uid,
			NULL, NULL, NULL, retval == 0);
		return retval;
	}
	/* Display account status. */
	if (passwd_flags & PASSWD_STATUS) {
		/* Auditing is not needed for displaying status */
		retval = pwdb_display_status(username);
		return retval;
	}
	/* Adjust aging parameters. */
	if (passwd_flags & PASSWD_AGING) {
		char aubuf[PATH_MAX];
		printf(_("Adjusting aging data for user %s.\n"), username);
		retval = pwdb_update_aging(username, min, max, warn, inact, -2);
		printf("%s: %s\n", progname,
		       (retval == 0) ? _("Success") : _("Error"));
		snprintf(aubuf, sizeof(aubuf), "changed-password-aging"
				" min=%li max=%li warn=%li inact=%li",
				min, max, warn, inact);
		audit_log_acct_message(audit_fd,  AUDIT_USER_MGMT,
			NULL, aubuf, NULL, pwd->pw_uid,
			NULL, NULL, NULL, retval == 0);
		return retval;
	}

	/* The standard behavior follows.  At this point we know for whom
	 * we are going to change a password, so let the invoking user
	 * know what's going on. */
	printf(_("Changing password for user %s.\n"), username);

	/* If we need to read the new password from stdin, read it and switch
	 * to the really-quiet stdin conversation function. */
	if (passwd_flags & PASSWD_STDIN) {
		/* PAM's documentation says that PAM_MAX_RESP_SIZE is the
		 * maximum supported length of the password, but in practice
		 * the code (including examples in the OSF RFC) often truncates
		 * data at PAM_MAX_RESP_SIZE - 1. So, refuse to use anything
		 * longer than PAM_MAX_RESP_SIZE - 1, to prevent users from
		 * setting a password they won't be able to use to log in. */
		char *ptr, newPassword[PAM_MAX_RESP_SIZE];
		int i;

		i = read(STDIN_FILENO, newPassword,
			 sizeof(newPassword));
		if (i < 0) {
			fprintf(stderr,
				_("%s: error reading from stdin: %s\n"), progname,
				strerror(errno));
			exit(1);
		}
		if (i == sizeof(newPassword)) {
			if (newPassword[i - 1] != '\n') {
				fprintf(stderr,
					_("%s: password too long, maximum is %zu"),
					progname, sizeof(newPassword) - 1);
				exit(1);
			}
			i--;
		}

		newPassword[i] = '\0';
		ptr = strchr(newPassword, '\n');
		if (ptr)
			*ptr = 0;
		conv.conv = stdin_conv;
		conv.appdata_ptr = strdup(newPassword);
	}

	/* Start up PAM. */
	retval = pam_start("passwd", username, &conv, &pamh);
	if (retval != PAM_SUCCESS) {
		fprintf(stderr,
			_("%s: unable to start pam: %s\n"), progname,
			pam_strerror(pamh, retval));
		exit(1);
	}

	if ((ttyn = ttyname(0)) != NULL) {	
		if (strncmp(ttyn, "/dev/", 5) == 0)
			tty_name = ttyn+5;
		else
			tty_name = ttyn;
		retval = pam_set_item(pamh, PAM_TTY, tty_name);
		if (retval != PAM_SUCCESS) {
			fprintf(stderr,
				_("%s: unable to set tty for pam: %s\n"), progname,
				pam_strerror(pamh, retval));
			pam_end(pamh, retval);
			exit(1);
		}
	}
#ifdef HAVE_PAM_FAIL_DELAY
	/* We have to pause on failure, so tell libpam the minimum amount
	 * of time it should wait after a failure. */
	retval = pam_fail_delay(pamh, PASSWD_FAIL_DELAY);
	if (retval != PAM_SUCCESS) {
		fprintf(stderr, _("%s: unable to set failure delay: %s\n"),
			progname, pam_strerror(pamh, retval));
		exit(1);
	}
#endif

	/* Go for it. Note: pam will send audit event. */
	retval = pam_chauthtok(pamh,
			       (passwd_flags & PASSWD_KEEP) ?
			       PAM_CHANGE_EXPIRED_AUTHTOK : 0);
	if (retval == PAM_SUCCESS) {
		/* We're done.  Tell the invoking user that it worked. */
		retval = pam_end(pamh, PAM_SUCCESS);
		if (passwd_flags & PASSWD_KEEP)
			printf(_("%s: expired authentication tokens updated successfully.\n"),
				progname);
		else
			printf(_("%s: all authentication tokens updated successfully.\n"),
				progname);
		retval = 0;
	} else {
		/* Horrors!  It failed.  Relay the bad news. */
		fprintf(stderr, "%s: %s\n", progname,
			pam_strerror(pamh, retval));
		pam_end(pamh, retval);
		retval = 1;
	}
	return retval;
}
