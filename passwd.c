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

/* Written by Cristian Gafton <gafton@redhat.com>
 * $Id$ */

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

#define _(String) String
#define N_(String) String

/* conversation function & corresponding structure */
static struct pam_conv conv = {
	misc_conv,
	NULL
};

const char *username = NULL;	/* username specified on the command line */
const char *progname = NULL;	/* the name of the program */
int passwd_flags = 0;		/* flags specified by root */

#define PASSWD_LOCK 	0x01	/* lock the password */
#define PASSWD_UNLOCK 	0x02	/* unlock the password, if locked */
#define PASSWD_DELETE 	0x04	/* delete the user's password */
#define PASSWD_KEEP 	0x08	/* keep un-expired tokens */
#define PASSWD_STATUS 	0x10	/* report the password status */
#define PASSWD_FORCE 	0x20	/* report the password status */
#define PASSWD_STDIN 	0x40	/* read the password from stdin (root only) */

#ifdef HAVE_PAM_FAIL_DELAY
#define PASSWD_FAIL_DELAY 	2000000	/* usec delay on failure */
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
parse_args(int argc, const char **argv)
{
	poptContext optCon;
	int delete = 0, force = 0, keep = 0, lock = 0, status = 0, unlock = 0;
	int use_stdin = 0;
	int rc;
	const char **extraArgs;
	struct poptOption options[] = {
		{"delete", 'd', POPT_ARG_NONE, &delete, 0,
		 "delete the password for the named account (root only)"},
		{"force", 'f', POPT_ARG_NONE, &force, 0,
		 "force operation\n"},
		{"keep-tokens", 'k', POPT_ARG_NONE, &keep, 0,
		 "keep non-expired authentication tokens"},
		{"lock", 'l', POPT_ARG_NONE, &lock, 0,
		 "lock the named account (root only)"},
		{"status", 'S', POPT_ARG_NONE, &status, 0,
		 "report password status on the named account (root only)"},
		{"stdin", '\0', POPT_ARG_NONE, &use_stdin, 0,
		 "read new tokens from stdin (root only)"},
		{"unlock", 'u', POPT_ARG_NONE, &unlock, 0,
		 "unlock the named account (root only)"},
		POPT_AUTOHELP {NULL, '\0', 0, NULL},
	};
	struct passwd *pw;

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

	/* The only flag which unprivileged users get to use is -k. */
	if ((passwd_flags & ~PASSWD_KEEP) && (getuid() != 0)) {
		fprintf(stderr, _("Only root can do that.\n"));
		exit(-2);
	}

	/* The rest of the flags are mutually-exclusive, except for --force. */
	if (passwd_flags) {
		int tmp = passwd_flags & ~PASSWD_FORCE;
		int count;
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
				_("%s: Only one flag may be specified.\n"),
				progname);
			exit(-2);
		}
	}

	/* Only root gets to specify a user name. */
	username = NULL;
	if ((extraArgs != NULL) && (extraArgs[0] != NULL)) {
		if (getuid() != 0) {
			/* The invoking user was not root. */
			fprintf(stderr,
				_("%s: Only root can specify a user name.\n"),
				progname);
			exit(-3);
		} else {
			/* The invoking user was root. */
			username = extraArgs[0];
			/* Sanity-check the user name*/
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

	/* Now if any of the -l, -u, -d, or -S options were given, and
	 * a username was not specified, bail out. */
	if ((passwd_flags & ~PASSWD_KEEP) && (username == NULL)) {
		fprintf(stderr, _("%s: This option requires a user name.\n"),
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
	pam_handle_t *pamh = NULL;

	/* Parse command-line arguments. */
	progname = basename(argv[0]);
	parse_args(argc, argv);

	/* Handle account locking request. */
	if (passwd_flags & PASSWD_LOCK) {
		printf(_("Locking password for user %s.\n"), username);
		retval = pwdb_lock_password(username);
		printf("%s: %s\n", progname,
		       retval ==
		       0 ? "Success" : "Error (password not set?)");
		return retval;
	}
	/* Handle account unlocking request. */
	if (passwd_flags & PASSWD_UNLOCK) {
		printf(_("Unlocking password for user %s.\n"), username);
		retval = pwdb_unlock_password(username,
					      passwd_flags & PASSWD_FORCE);
		printf("%s: %s\n", progname,
		       retval == 0 ? _("Success.") :
		       retval == -2 ? _("Unsafe operation (use -f to force).") :
		       _("Error (password not set?)"));
		return retval;
	}
	/* Handle password clearing request. */
	if (passwd_flags & PASSWD_DELETE) {
		printf(_("Removing password for user %s.\n"), username);
		retval = pwdb_clear_password(username);
		printf("%s: %s\n", progname,
		       retval == 0 ? _("Success") : _("Error"));
		return retval;
	}
	/* Display account status. */
	if (passwd_flags & PASSWD_STATUS) {
		retval = pwdb_display_status(username);
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

		i = read(STDIN_FILENO, newPassword, sizeof(newPassword) - 1);
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
			       PAM_CHANGE_EXPIRED_AUTHTOK :
			       0);
	if (retval == PAM_SUCCESS) {
		/* We're done.  Tell the invoking user that it worked. */
		retval = pam_end(pamh, PAM_SUCCESS);
		pamh = NULL;
		if (passwd_flags & PASSWD_KEEP) {
			printf(_("passwd: expired authentication tokens updated successfully.\n"));
		} else {
			printf(_("passwd: all authentication tokens updated successfully.\n"));
		}
		retval = 0;
	} else {
		/* Horrors!  It failed.  Relay the bad news. */
		fprintf(stderr, _("passwd: %s\n"), pam_strerror(pamh, retval));
		retval = pam_end(pamh, PAM_SUCCESS);
		pamh = NULL;
		retval = 1;
	}
	return retval;
}
