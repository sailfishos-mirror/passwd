/*
 * Copyright Red Hat, Inc., 1998, 1999, 2002.
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
 * Written by Cristian Gafton <gafton@redhat.com>
 */

#ident "$Id$"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <paths.h>
#include <limits.h>
#include <getopt.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "pwdb.h"
#include "version.h"

static char *shell = NULL;	/* new shell */
static char *o_shell = NULL;	/* original shell */
static char *user_name = NULL;	/* the account name */

/* command line flags */
static int s_flg = 0;		/* -s flag = change shell */
static int l_flg = 0;		/* -l flag = list shells */

const char *progname = NULL;

/*
 * the structure pointing at the conversation function for
 * auth and changing the password
 */
static struct pam_conv conv = {
	misc_conv,
	NULL
};

static void
usage(void)
{
	printf("Usage: %s [-s new_shell] [-l] [username]\n", progname);
}

static int
invalid_shell(const char *t_shell)
{
	FILE *fp;
	char buf[BUFSIZ];
	char *s = NULL;

	if (*t_shell != '/' || strlen(t_shell) > PATH_MAX) {
		/* this is for sure not a shell */
		return -1;
	}

	fp = fopen(_PATH_SHELLS, "r");
	if (fp == (FILE *) NULL) {
		fprintf(stderr, "%s: Could not read %s\n",
			progname, _PATH_SHELLS);
		return -1;
	}

	do {
		memset(buf, 0, BUFSIZ);
		s = fgets(buf, BUFSIZ, fp);
		if (s == NULL) {
			break;
		}
		if (*s != '/') {
			/* this is not a shell line */
			continue;
		}
		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';
		if (strcmp(t_shell, buf) == 0) {
			/* this is our shell */
			fclose(fp);
			return 0;
		}
	} while (s != NULL);
	fclose(fp);
	/* most likely the shell is not valid */
	if (getuid())
		return -1;
	else {			/* root is allowed to set any shell he wants */
		fprintf(stderr,
			"%s: Warning, this shell is not listed in %s.\n",
			progname, _PATH_SHELLS);
		return 0;
	}
	return -1;		/* not reached */
}

static void
list_shells(void)
{
	char *shell = NULL;
	setusershell();
	while ((shell = getusershell()) != NULL) {
		printf("%s\n", shell);
	}
	endusershell();
}

/* Ask the user for input... */
static char *
ask_user_once(const char *prompt, const char *def)
{
	char *t;
	char *t1;

	printf("%s [%s]: ", prompt, def);
	t = read_string();
	if (t == NULL) {
		/* error reading input - EOF ?? */
		fprintf(stderr,
			"%s: EOF encountered while reading from stdin.\n",
			progname);
		return (char *) -1;
	}
	if (*t == '\0') {
		/* we need the default value... */
		free(t);
		return x_strdup(def);
	}
	/* if all we've got is a ' ', the user wants this entry deleted */
	if (strcmp(t, " ") == 0) {
		free(t);
		return x_strdup("");
	}
	/* else, we have a new entry we have to verify */
	if (invalid_shell(t)) {
		/* invalid input */
		fprintf(stderr, "%s: Your entry is not a valid shell\n",
			progname);
		free(t);
		return (char *) -1;
	}
	t1 = x_strdup(t);	/* most likely t has to much space alloced */
	free(t);
	return t1;
}

static char *
ask_user(const char *prompt, const char *def)
{
	char *t;

	if (prompt == NULL)
		return NULL;
	if (def == NULL)
		def = "";
	do {
		t = ask_user_once(prompt, def);
	} while (t == (char *) -1);
	return t;
}

static void
interactive(void)
{
	printf("Changing login shell for user '%s'.\n", user_name);
	shell = ask_user("New Shell", o_shell);
}

int
main(int argc, char *argv[])
{
	int arg;
	int retval;
	pam_handle_t *pamh = NULL;

	int option_index = 0;

	static struct option options[] = {
		{"shell", required_argument, NULL, 's'},
		{"list-shells", no_argument, NULL, 'l'},
		{"help", no_argument, NULL, 'u'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0},
	};

	/* init things */
	progname = basename(argv[0]);

	while ((arg = getopt_long(argc, argv, "s:uvl",
				  options, &option_index)) != EOF) {
		switch (arg) {
		case 's':
			s_flg++;
			shell = optarg;
			if (invalid_shell(optarg)) {
				fprintf(stderr,
					"%s: The shell entered is invalid.\n",
					progname);
				exit(-9);
			}
			break;
		case 'l':
			l_flg++;
			break;
		case 'u':
			usage();
			exit(0);
		case 'v':
			version();
			exit(0);
		default:
			usage();
			exit(-1);
		}
	}

	user_name = NULL;
	if (argc > optind) {
		/* username supplied in command line */
		if (getuid() != 0) {
			fprintf(stderr,
				"%s: Only root can specify a user name\n",
				progname);
			exit(-2);
		} else {
			/* username specified... */
			struct passwd *pw;
			user_name = argv[optind];
			/* test the username for length */
			if (strlen(user_name) > MAX_USERNAMESIZE) {
				fprintf(stderr,
					"%s: The username supplied is too long\n",
					progname);
				exit(-3);
			}
			pw = getpwnam(user_name);
			if (pw == (struct passwd *) NULL) {
				fprintf(stderr,
					"%s: Unknown user name '%s'\n",
					progname, user_name);
				exit(-4);
			}
			/* make a copy we can work with */
			o_shell = x_strdup(pw->pw_shell);
		}
	}

	/* if no username is supplied, assume the current uid */
	if (user_name == NULL) {
		struct passwd *pw;
		pw = getpwuid(getuid());
		if (pw == (struct passwd *) NULL || pw->pw_name == NULL) {
			fprintf(stderr, "%s: Could not identify you!\n",
				progname);
			exit(-2);
		}
		user_name = x_strdup(pw->pw_name);
		/* make a copy we can work with */
		o_shell = x_strdup(pw->pw_shell);
	}

	if (l_flg + s_flg > 1) {
		/* To many options */
		fprintf(stderr,
			"%s: Options -l and -s can not be given at the same time\n",
			progname);
		exit(-2);
	}

	/* Check for the easy part */
	if (l_flg) {
		printf("This is the list of available shells:\n");
		list_shells();
		exit(0);
	}

	/* verify the fields we were passed */
	if (s_flg && invalid_shell(shell))
		exit(-3);

	/* if no flags were given in the command line, we must go interactive */
	if (!s_flg)
		interactive();

	retval = pam_start("chsh", user_name, &conv, &pamh);
	if (retval != PAM_SUCCESS) {
		fprintf(stderr,
			"%s: Could not initialize PAM authetication.\n",
			progname);
		exit(-9);
	}

	retval = pam_authenticate(pamh, 0);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		fprintf(stderr, "%s: Authentication failure: %s\n",
			progname, pam_strerror(pamh, retval));
		exit(-2);
	}

	retval = pam_acct_mgmt(pamh, 0);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		fprintf(stderr, "%s: Account processing error: %s\n",
			progname, pam_strerror(pamh, retval));
		exit(-2);
	}

	retval = pwdb_update_shell(user_name, shell);
	if (retval != 0) {
		fprintf(stderr, "%s: Error changing login shell.\n",
			progname);
		if (pamh != NULL)
			pam_end(pamh, PAM_ABORT);
		exit(-1);
	}

	/* if interactive, we have some free() to call) */
	if (!s_flg)
		free(shell);
	free(o_shell);

	/* all done */
	if (pamh != NULL)
		retval = pam_end(pamh, PAM_SUCCESS);
	exit(0);
}
