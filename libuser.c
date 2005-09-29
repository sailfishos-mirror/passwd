/*
 * Copyright Red Hat, Inc., 2002.
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
 * This file contains libuser wrappers with prototypes which match the
 * declarations in pwdb.h.  Where possible, behavior is kept as close
 * to that of the previous versions as possible.
 */

#ident "$Id$"

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <libuser/user.h>
#include "pwdb.h"

#ifdef LIBUSER

extern const char *progname;

#define _(String) String
#define CHECK_ERROR(x) \
if (x != NULL) { \
	fprintf(stderr, "%s: Error %d - %s.\n", \
		progname, __LINE__, lu_strerror(x)); \
	lu_error_free(&x); \
	return -1; \
}

static struct lu_context *libuser = NULL;

/* Shut down libuser. */
static int
shutdown_libuser(void)
{
	lu_end(libuser);
	libuser = NULL;
	return 0;
}

/* Start up the library, suggesting the name of the user which was
 * passed in as the name the library should use if it needs to
 * authenticate to data sources. */
static int
startup_libuser(const char *user)
{
	struct lu_error *error = NULL;
	if (libuser != NULL) {
		shutdown_libuser();
	}
	libuser = lu_start(user, lu_user, NULL, NULL,
			   lu_prompt_console, NULL, &error);
	if (libuser == NULL) {
		fprintf(stderr,
			_("passwd: libuser initialization error.\n"));
		_exit(1);
	}
	CHECK_ERROR(error);
	return 0;
}

/* Lock an account. */
int
pwdb_lock_password(const char *username)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	gboolean started = FALSE;
	if (libuser == NULL) {
		startup_libuser("root");
		started = TRUE;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		if (lu_user_lock(libuser, ent, &error)) {
			retval = 0;
		}
	}
	lu_ent_free(ent);
	CHECK_ERROR(error);
	if (started) {
		shutdown_libuser();
	}
	return retval;
}

int
pwdb_unlock_password(const char *username, int force)
{
#if 0
	fprintf(stderr,
		"Warning: unlocked password for %s is the empty string.\n"
		"Use the -f flag to force the creation of a passwordless account.\n",
		username);
#endif
	int retval = 1, i;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValueArray *values;
	GValue *value;
	const char *current = NULL;
	gboolean started = FALSE;
	if (libuser == NULL) {
		startup_libuser("root");
		started = TRUE;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		current = NULL;
		value = NULL;
		values = lu_ent_get(ent, LU_SHADOWPASSWORD);
		if (values == NULL) {
			values = lu_ent_get(ent, LU_USERPASSWORD);
		}
		if (values) {
			value = g_value_array_get_nth(values, 0);
		}
		if (value) {
			current = lu_value_strdup(value);
		}
		if (current && (force == 0)) {
			/* Search for a non-locking character. */
			for (i = 0; (current[i] == '!'); i++) {
				/*nothing */
			};
			/* If the first non-locking character is the end of the
			 * string, */
			if (current[i] == '\0') {
				/* warn the admin, because this is probably a
				 * bad idea. */
				retval = -2;
			}
		}
		if (retval != -2) {
			/* Go blind, or force it. */
			if (lu_user_unlock(libuser, ent, &error)) {
				retval = 0;
			}
		}
	}
	lu_ent_free(ent);
	CHECK_ERROR(error);
	if (started) {
		shutdown_libuser();
	}
	return retval;
}

/* Try to remove a user's password.  Note that some of the underlying modules
 * libuser uses don't support this. */
int
pwdb_clear_password(const char *username)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	gboolean started = FALSE;
	if (libuser == NULL) {
		startup_libuser("root");
		started = TRUE;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		if (lu_user_removepass(libuser, ent, &error)) {
			retval = 0;
		}
	}
	lu_ent_free(ent);
	CHECK_ERROR(error);
	if (started) {
		shutdown_libuser();
	}
	return retval;
}

int
pwdb_display_status(const char *username)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValue *value;
	GValueArray *values;
	char *current;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		current = NULL;
		value = NULL;
		values = lu_ent_get(ent, LU_SHADOWPASSWORD);
		if (values == NULL) {
			values = lu_ent_get(ent, LU_USERPASSWORD);
		}
		if (values) {
			value = g_value_array_get_nth(values, 0);
		}
		if (value) {
			current = lu_value_strdup(value);
		}
		if (current) {
			if (strlen(current) == 0) {
				printf(_("Empty password.\n"));
			} else if (current[0] == '!') {
				printf(_("Password locked.\n"));
			} else if (current[0] == '$') {
				if (strncmp(current, "$1$", 3) == 0) {
					printf(_
					       ("Password set, MD5 crypt.\n"));
				} else if (strncmp(current, "$2a$", 4) ==
					   0) {
					printf(_
					       ("Password set, blowfish crypt.\n"));
				} else {
					printf(_
					       ("Password set, unknown crypt variant.\n"));
				}
			} else if (strlen(current) < 11) {
				printf(_
				       ("Alternate authentication scheme in use.\n"));
			} else {
				printf(_("Password set, DES crypt.\n"));
			}
			g_free(current);
		} else {
			printf(_("No password set.\n"));
		}
	} else {
		printf(_("Unknown user.\n"));
	}

	CHECK_ERROR(error);

	shutdown_libuser();
	return retval;
}

int
pwdb_update_gecos(const char *username, const char *gecos)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValue value;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		lu_ent_clear(ent, LU_GECOS);

		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, gecos);

		lu_ent_add(ent, LU_GECOS, &value);
		g_value_unset(&value);

		if (lu_user_modify(libuser, ent, &error)) {
			retval = 0;
		}
	}

	CHECK_ERROR(error);

	shutdown_libuser();
	return retval;
}

int
pwdb_update_shell(const char *username, const char *shell)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValue value;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		lu_ent_clear(ent, LU_LOGINSHELL);

		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, shell);

		lu_ent_add(ent, LU_LOGINSHELL, &value);
		g_value_unset(&value);

		if (lu_user_modify(libuser, ent, &error)) {
			retval = 0;
		}
	}

	CHECK_ERROR(error);

	shutdown_libuser();
	return retval;
}


int
pwdb_update_aging(const char *username,
		  long min, long max, long warn, long inact)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValue value;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_LONG);

		if (!lu_ent_get(ent, LU_SHADOWMIN) &&
		    !lu_ent_get(ent, LU_SHADOWMAX) &&
		    !lu_ent_get(ent, LU_SHADOWWARNING) &&
		    !lu_ent_get(ent, LU_SHADOWINACTIVE)) {
			fprintf(stderr, _("passwd: user account has no support "
					  "for password aging\n"));
			shutdown_libuser();
			return retval;
		}

		if (min != -2) {
			g_value_set_long(&value, min);
			lu_ent_clear(ent, LU_SHADOWMIN);
			lu_ent_add(ent, LU_SHADOWMIN, &value);
		}
		if (max != -2) {
			g_value_set_long(&value, max);
			lu_ent_clear(ent, LU_SHADOWMAX);
			lu_ent_add(ent, LU_SHADOWMAX, &value);
		}
		if (warn != -2) {
			g_value_set_long(&value, warn);
			lu_ent_clear(ent, LU_SHADOWWARNING);
			lu_ent_add(ent, LU_SHADOWWARNING, &value);
		}
		if (inact != -2) {
			g_value_set_long(&value, inact);
			lu_ent_clear(ent, LU_SHADOWINACTIVE);
			lu_ent_add(ent, LU_SHADOWINACTIVE, &value);
		}
		g_value_unset(&value);

		if (lu_user_modify(libuser, ent, &error)) {
			retval = 0;
		}
	}

	CHECK_ERROR(error);

	shutdown_libuser();
	return retval;
}

#endif
