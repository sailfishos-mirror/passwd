/* 
 * passwd - 	a (yet another?) password changing program for RH systems
 *		making use of PAM and PWDB
 */

/*
 * Copyright Red Hat Software, Inc., 1998, 1999.
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

/*
 *
 * Written by Cristian Gafton <gafton@redhat.com>
 * $Id$
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pwd.h>
#include <popt.h>

#include "pwdb.h"

/* conversation function & corresponding structure */
static struct pam_conv conv = {
    misc_conv,
    NULL
};

const char *username	= NULL; /* username specified on the command line */
const char *progname	= NULL; /* the name of the program */
int passwd_flags 	= 0;	/* flags specified by root */

#define PASSWD_LOCK 	0x01 /* lock the password */
#define PASSWD_UNLOCK 	0x02 /* unlock the password, if locked */
#define PASSWD_DELETE 	0x04 /* delete the user's password */
#define PASSWD_KEEP 	0x08 /* keep un-expired tokens */
#define PASSWD_STATUS 	0x10 /* report the password status */
#define PASSWD_FORCE 	0x20 /* report the password status */
#define PASSWD_STDIN 	0x40 /* read the password from stdin (root only) */

#ifdef HAVE_PAM_FAIL_DELAY
#define PASSWD_FAIL_DELAY 	2000000 /* usec delay on failure */
#endif

static int stdin_conv(int num_msg, const struct pam_message **msgm,
		      struct pam_response **response, void *appdata_ptr) {
    struct pam_response *reply;
    int count;

    if (num_msg <= 0)
	return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
					   sizeof(struct pam_response));
    if (reply == NULL) {
	return PAM_CONV_ERR;
    }

    for (count=0; count < num_msg; ++count) {
	reply[count].resp_retcode = 0;
	reply[count].resp = strdup(appdata_ptr);
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;
}

static void parse_args(int argc, char * const argv[])
{
    poptContext optCon;
    int delete = 0, force = 0, keep = 0, lock = 0, status = 0, unlock = 0;
    int stdin = 0;
    int rc;
    const char ** extraArgs;
    struct poptOption options[] = {
	{ "delete", 'd', POPT_ARG_NONE, &delete, 0,
	    "delete the password for the named account (root only)" },
	{ "force", 'f', POPT_ARG_NONE, &force, 0,
	    "force operation\n" },
	{ "keep-tokens", 'k', POPT_ARG_NONE, &keep, 0,
	    "keep non-expired authentication tokens" },
	{ "lock", 'l', POPT_ARG_NONE, &lock, 0,
	    "lock the named account (root only)" },
	{ "status", 'S', POPT_ARG_NONE, &status, 0,
	    "report password status on the named account (root only)" },
	{ "stdin", '\0', POPT_ARG_NONE, &stdin, 0,
	    "read new tokens from stdin (root only)" },
	{ "unlock", 'u', POPT_ARG_NONE, &unlock, 0,
	    "unlock the named account (root only)" },
	POPT_AUTOHELP
	{ NULL, '\0', 0, NULL },
    };

    optCon = poptGetContext("passwd", argc, (char **) argv, options,0);
    poptSetOtherOptionHelp(optCon, "[OPTION...] <accountName>");

    if ((rc = poptGetNextOpt(optCon)) < -1) {
	fprintf(stderr, "%s: bad argument %s: %s\n", progname,
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS), 
		poptStrerror(rc));
	exit(-3);
    }

    extraArgs = poptGetArgs(optCon);

    if (keep)
	passwd_flags |= PASSWD_KEEP;
    if (lock)
	passwd_flags |= PASSWD_LOCK;
    if (unlock)
	passwd_flags |= PASSWD_UNLOCK;
    if (status)
	passwd_flags |= PASSWD_STATUS;
    if (delete)
	passwd_flags |= PASSWD_DELETE;
    if (force)
	passwd_flags |= PASSWD_FORCE;
    if (stdin)
	passwd_flags |= PASSWD_STDIN;

    printf("Flags :%0x\n", passwd_flags);
    
    /* the only flag available to an user id -k */
    if ((passwd_flags & ~PASSWD_KEEP) && getuid()) {
	fprintf(stderr, "Only root can do that\n");
	exit(-2);
    }
    /* now, only one flag can be active */
    if (passwd_flags) {
	int tmp = passwd_flags & ~PASSWD_FORCE;
	int count;
	for(count = 0; tmp ; tmp = tmp >> 1)
	    if (tmp & 0x01)
		count++;
	if (count > 1) {
	    fprintf(stderr, "%s: Only one flag may be specified.\n",
		    progname);
	    exit(-2);
	}
    }

    /* now, only root can specify an username */
    username = NULL;
    if (extraArgs && extraArgs[0]) {
	if (getuid()) {
	    /* non root */
	    fprintf(stderr, "%s: Only root can specify a username\n",
		    progname);
	    exit(-3);
	} else {
	    username = extraArgs[0];
	    /* test the username for length */
	    if (strlen(username) > MAX_USERNAMESIZE) {
		fprintf(stderr, "%s: The username supplied is too long\n",
			progname);
		exit(-3);
	    }
	}

	if (extraArgs[1]) {
	    fprintf(stderr, "%s: Only one user name may be specified\n",
		    progname);
	    exit(-3);
	}
    }

    /* now if any of the ludS options were given and the username is
     * not specified, bail out */
    if ((passwd_flags & ~PASSWD_KEEP) && (username == NULL)) {
	fprintf(stderr, "%s: This option requires a username\n",
		progname);
	exit(-2);
    }
    
    /* the username we are changing password for */
    if (username == (char *)NULL) {
	/* find out who are we */
	struct passwd *pw;
	pw = getpwuid(getuid());
	if (pw == (struct passwd *)NULL) {
	    fprintf(stderr, "%s: Can not identify you !\n", progname);
	    exit(-3);
	}	
	username = x_strdup(pw->pw_name);
    } else {
	/* username specified... */
	struct passwd *pw;
	pw = getpwnam(username);
	if (pw == (struct passwd *)NULL) {
	    fprintf(stderr, "%s: Unknown user name '%s'\n",
		    progname, username);
	    exit(-4);
	}
	printf("Changing password for user %s\n", username);
    }
}

int main(int argc, char * const argv[])
{
    int retval;
    pam_handle_t *pamh=NULL;

    /* obtain user's specific request */
    progname = basename(argv[0]);
    parse_args(argc, argv);

    if (passwd_flags & PASSWD_LOCK) {
	printf("Locking password for user %s\n", username);
	retval = pwdb_lock_password(username);
	printf("%s: %s\n", progname,
	       retval==0 ? "Success" : "Error (passwd not set ?)");
	return retval;
    }
    if (passwd_flags & PASSWD_UNLOCK) {
	printf("Unlocking password for user %s\n", username);
	retval = pwdb_unlock_password(username, passwd_flags & PASSWD_FORCE);
	printf("%s: %s\n", progname,
	       retval==0 ? "Success" :
	       retval==-2 ?"Unsafe operation" : "Error (passwd not set ?)");
	return retval;
    }
    if (passwd_flags & PASSWD_DELETE) {
	printf("Removing password for user %s\n", username);
	retval = pwdb_clear_password(username);
	printf("%s: %s\n", progname, retval==0 ? "Success" : "Error");
	return retval;
    }
    if (passwd_flags & PASSWD_STATUS) {
	retval = pwdb_display_status(username);
	return retval;
    }

    /* The standard behavior follows... */
    /* here we know whose passwords are to be changed and whether
       we'll change everything or just the expired ones */

    if (passwd_flags & PASSWD_STDIN) {
	char newPassword[80];
	int i;

	i = read(0, newPassword, sizeof(newPassword) - 1);
	newPassword[i - 1] = '\0';
	conv.conv = stdin_conv;
	conv.appdata_ptr = strdup(newPassword);
    }

    retval = pam_start("passwd", username, &conv, &pamh);

#ifdef HAVE_PAM_FAIL_DELAY
    /* have to pause on failure. At least this long (doubles..) */
    retval = pam_fail_delay(pamh, PASSWD_FAIL_DELAY);
    if (retval != PAM_SUCCESS) {
	fprintf(stderr, "passwd: unable to set failure delay\n");
	exit(1);
    }
#endif /* HAVE_PAM_FAIL_DELAY */

    while (retval == PAM_SUCCESS) {      /* use loop to avoid goto... */
	/* the user is authenticated by the passwd module; change
	   the password(s) too. */
	retval = pam_chauthtok(pamh, (passwd_flags & PASSWD_KEEP)
			       ? PAM_CHANGE_EXPIRED_AUTHTOK : 0 );
	if (retval != PAM_SUCCESS)
	    break;
	/* all done */
	retval = pam_end(pamh, PAM_SUCCESS);
	if (retval != PAM_SUCCESS)
	    break;
	/* quit gracefully */
	printf( "passwd: %s authentication tokens updated successfully\n",
		(passwd_flags & PASSWD_KEEP) ? "expired":"all" );
	exit(0);
    }

    if (retval != PAM_SUCCESS)
	fprintf(stderr, "passwd: %s\n", pam_strerror(pamh, retval));

    if (pamh != NULL) {
	(void) pam_end(pamh,PAM_SUCCESS);
	pamh = NULL;
    }

    exit(1);
}
