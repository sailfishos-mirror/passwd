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
#include <getopt.h>

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

#ifdef HAVE_PAM_FAIL_DELAY
#define PASSWD_FAIL_DELAY 	2000000 /* usec delay on failure */
#endif

static void usage(void) {	
    fprintf(stderr, "usage: passwd [-k] [-l] [-u [-f]] [-d] [-S] [ username ]\n"
	    "     \t-k        - keep non-expired authentication tokens\n"
	    "  (*)\t-l        - lock the named account\n"
	    "  (*)\t-u        - unlock the named account\n"
	    "     \t-f        - force operation\n"
	    "  (*)\t-d        - delete the password for the named account\n"
	    "  (*)\t-S        - report password status on the named account\n"
	    "  (*)\tusername  - update tokens for named user\n"
	    "\n (*) - option available only to root\n"
	    );
}

static void parse_args(int argc, char * const argv[])
{
    while (1) {
	int c;

	c = getopt(argc, argv, "klufdS");
	if (c == -1)
	    break;
	switch (c) {
	    case 'k': passwd_flags |= PASSWD_KEEP; break;
	    case 'l': passwd_flags |= PASSWD_LOCK; break;
	    case 'u': passwd_flags |= PASSWD_UNLOCK; break;
	    case 'S': passwd_flags |= PASSWD_STATUS; break;
	    case 'd': passwd_flags |= PASSWD_DELETE; break;
	    case 'f': passwd_flags |= PASSWD_FORCE; break;
	    default:
		usage();
		exit(-1);
	}
    }

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
	    fprintf(stderr, "%s: Only one flag can be specified.\n",
		    progname);
	    exit(-2);
	}
    }

    /* now, only root can specify an username */
    username = NULL;
    if (argc - optind > 0) {
	if (getuid()) {
	    /* non root */
	    fprintf(stderr, "%s: Only root can specify a username\n",
		    progname);
	    exit(-3);
	} else {
	    username = argv[optind];
	    /* test the username for length */
	    if (strlen(username) > MAX_USERNAMESIZE) {
		fprintf(stderr, "%s: The username supplied is too long\n",
			progname);
		exit(-3);
	    }
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
	fprintf(stderr,
		"passwd: %s authentication tokens updated successfully\n",
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
