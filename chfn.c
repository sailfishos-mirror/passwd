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
#include <getopt.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "pwdb.h"
#include "version.h"

/* GECOS field length... is this enough ? */
#define GECOS_LENGTH		64
#define FORBIDDEN_CHARS		":,="

static char *full_name = NULL;	/* full user name */
static char *office = NULL;	/* office */
static char *office_ph = NULL;	/* office phone */
static char *home_ph = NULL;	/* home phone */
static char *other = NULL;	/* other info for the gecos... */

/* same style, the original values */
static char *o_full_name = NULL;	/* full user name */
static char *o_office = NULL;	/* office */
static char *o_office_ph = NULL;	/* office phone */
static char *o_home_ph = NULL;	/* home phone */
static char *o_other = NULL;	/* other info for the gecos... */

static char *user_name = NULL;	/* the account name */

/* command line flags */
static int f_flg = 0;		/* -f flag = change full name */
static int o_flg = 0;		/* -o flag = change office name */
static int p_flg = 0;		/* -p flag = change office phone */
static int h_flg = 0;		/* -h flag = change home phone number */
static int O_flg = 0;		/* -O flag = change the other information */

const char *progname = NULL;

/*
 * the structure pointing at the conversation function for
 * auth and changing the password
 */
static struct pam_conv conv = {
	misc_conv,
	NULL
};

/*
 * A function to process already existing gecos information
 */
static void
process_gecos(char *gecos)
{
	char *ptr[5];		/* pointers to the fields in the gecos string */
	char *idx;
	int i;

	/* sanity check */
	if (gecos == NULL)
		return;

	for (i = 0; i < 5; i++)
		ptr[i] = NULL;

	ptr[0] = idx = gecos;
	i = 1;

	while (*idx) {
		if (*idx == ',') {	/* we found a new field... */
			*idx = '\0';
			ptr[i++] = idx + 1;
		}
		if (i > 4)	/* avoid processing invalid fields */
			break;
		idx++;
	}
	/* now things are simple ... */
	o_full_name = ptr[0] ? ptr[0] : "";
	o_office = ptr[1] ? ptr[1] : "";
	o_office_ph = ptr[2] ? ptr[2] : "";
	o_home_ph = ptr[3] ? ptr[3] : "";
	o_other = ptr[4] ? ptr[4] : "";
}

/*
 * invalid_field - insure that a field contains all legal characters
 *
 * The supplied field is scanned for non-printing and other illegal
 * characters.  If any illegal characters are found, invalid_field
 * returns -1.  Zero is returned for success.
 */

static int
invalid_field(const char *field, const char *illegal)
{
	const char *cp;

	if (illegal == NULL)
		illegal = FORBIDDEN_CHARS;

	for (cp = field; *cp && isprint(*cp) && !strchr(illegal, *cp);
	     cp++);
	if (*cp)
		return -1;
	else
		return 0;
}

/*
 * A simple function to compute the gecos field size
 */
#define s_size(a,b) a?strlen(a):(b?strlen(b):1)
static int
gecos_size(void)
{
	int len = 0;

	len += s_size(full_name, o_full_name);
	len += s_size(office, o_office);
	len += s_size(office_ph, o_office_ph);
	len += s_size(home_ph, o_home_ph);
	len += s_size(other, o_other);
	return len;
}

static void
usage(void)
{
	printf("Usage: %s [-f full_name] [-o office ] [-p office_phone]\n"
	       "\t[-h home_phone] [-O other] [username]\n", progname);
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
	if (*t == ' ' && strlen(t) == 1) {
		free(t);
		return x_strdup("");
	}
	/* else, we have a new entry we have to verify */
	if (invalid_field(t, FORBIDDEN_CHARS)) {
		/* invalid input */
		fprintf(stderr,
			"%s: Input contains forbidden chars (%s)\n",
			progname, FORBIDDEN_CHARS);
		free(t);
		return (char *) -1;
	}
	if (strlen(t) > GECOS_LENGTH) {
		fprintf(stderr,
			"%s: Your entry is too long (%d chars limit)\n",
			progname, GECOS_LENGTH);
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
	printf("Changing finger information for user '%s'.\n"
	       "A single space will clear an entry.\n", user_name);
	full_name = ask_user("Full Name", o_full_name);
	office = ask_user("Office", o_office);
	office_ph = ask_user("Office Phone", o_office_ph);
	home_ph = ask_user("Home Phone", o_home_ph);
	other = ask_user("Other", o_other);
}

/* returns -1 if a given field is invalid */
static int
verify_field(const char *field, const char *msg)
{
	if (msg == NULL)
		msg = "";
	if (invalid_field(field, FORBIDDEN_CHARS)) {
		/* invalid input */
		fprintf(stderr,
			"%s: Input field %s contains forbidden chars (%s)\n",
			progname, msg, FORBIDDEN_CHARS);
		return -1;
	}
	if (strlen(field) > GECOS_LENGTH) {
		fprintf(stderr,
			"%s: Your %s entry is too long (%d chars limit)\n",
			progname, msg, GECOS_LENGTH);
		return -1;
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	int arg;
	int retval;
	pam_handle_t *pamh = NULL;
	char *new_gecos = NULL;
	char *o_gecos = NULL;
	int option_index = 0;

	static struct option options[] = {
		{"full-name", required_argument, NULL, 'f'},
		{"office", required_argument, NULL, 'o'},
		{"office-phone", required_argument, NULL, 'p'},
		{"home-phone", required_argument, NULL, 'h'},
		{"other", required_argument, NULL, 'O'},
		{"help", no_argument, NULL, 'u'},
		{"usage", no_argument, NULL, 'u'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0},
	};

	/* init things */
	progname = basename(argv[0]);

	while ((arg = getopt_long(argc, argv, "f:o:p:h:O:uv",
				  options, &option_index)) != EOF) {
		switch (arg) {
		case 'f':
			f_flg++;
			full_name = optarg;
			if (verify_field(optarg, "full name") != 0) {
				fprintf(stderr, "%s: Aborting.\n",
					progname);
				exit(-9);
			}
			break;
		case 'o':
			o_flg++;
			office = optarg;
			if (verify_field(optarg, "office") != 0) {
				fprintf(stderr, "%s: Aborting.\n",
					progname);
				exit(-9);
			}
			break;
		case 'h':
			h_flg++;
			home_ph = optarg;
			if (verify_field(optarg, "home phone") != 0) {
				fprintf(stderr, "%s: Aborting.\n",
					progname);
				exit(-9);
			}
			break;
		case 'p':
			p_flg++;
			office_ph = optarg;
			if (verify_field(optarg, "office phone") != 0) {
				fprintf(stderr, "%s: Aborting.\n",
					progname);
				exit(-9);
			}
			break;
		case 'O':
			O_flg++;
			other = optarg;
			if (verify_field(optarg, "other") != 0) {
				fprintf(stderr, "%s: Aborting.\n",
					progname);
				exit(-9);
			}
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
			o_gecos = x_strdup(pw->pw_gecos);
			process_gecos(o_gecos);
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
		o_gecos = x_strdup(pw->pw_gecos);
		process_gecos(o_gecos);
	}

	/* verify the fields we were passed */
	if (f_flg && invalid_field(full_name, FORBIDDEN_CHARS))
		exit(-3);
	if (o_flg && invalid_field(office, FORBIDDEN_CHARS))
		exit(-3);
	if (p_flg && invalid_field(office_ph, FORBIDDEN_CHARS))
		exit(-3);
	if (h_flg && invalid_field(home_ph, FORBIDDEN_CHARS))
		exit(-3);
	if (O_flg && invalid_field(other, FORBIDDEN_CHARS))
		exit(-3);

	/* if no flags were given in the command line, we must go interactive */
	if (f_flg + o_flg + p_flg + h_flg + O_flg == 0)
		interactive();

	retval = pam_start("chfn", user_name, &conv, &pamh);
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

	new_gecos = malloc(gecos_size() + 5);
	if (new_gecos == NULL) {
		fprintf(stderr, "%s: Out of memory.\n", progname);
		exit(-2);
	}
	/* Build the new gecos field */
	snprintf(new_gecos, gecos_size() + 5,
		 "%.*s,%.*s,%.*s,%.*s,%.*s",
		 GECOS_LENGTH, full_name ? full_name : o_full_name,
		 GECOS_LENGTH, office ? office : o_office,
		 GECOS_LENGTH, office_ph ? office_ph : o_office_ph,
		 GECOS_LENGTH, home_ph ? home_ph : o_home_ph,
		 GECOS_LENGTH, other ? other : o_other);

	/* if interactive, we have some free() to call) */
	if (f_flg + o_flg + p_flg + h_flg + O_flg == 0) {
		free(full_name);
		free(office);
		free(office_ph);
		free(home_ph);
		free(other);
	}
	free(o_gecos);

	retval = pwdb_update_gecos(user_name, new_gecos);
	if (retval != 0) {
		fprintf(stderr, "%s: Error updating GECOS information.\n",
			progname);
		if (pamh != NULL)
			pam_end(pamh, PAM_ABORT);
		exit(-1);
	}

	/* all done */
	if (pamh != NULL)
		retval = pam_end(pamh, PAM_SUCCESS);
	exit(0);
}
