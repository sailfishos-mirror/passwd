/*
 * Copyright Red Hat, Inc., 2002, 2006, 2015.
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

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

/* GValueArray is a part of external API of libuser; warnings about it being
   deprecated do no good. */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_30

#include <libuser/user.h>
#include <libintl.h>
#include "pwdb.h"

extern const char *progname;

#define CHECK_ERROR(x) \
if (x != NULL) { \
	fprintf(stderr, "%s: Libuser error at line: %d - %s.\n", \
		progname, __LINE__, lu_strerror(x)); \
	lu_error_free(&x); \
	return -1; \
}

static struct lu_context *libuser = NULL;

/* Shut down libuser. */
static void
shutdown_libuser(void)
{
	lu_end(libuser);
	libuser = NULL;
}

/* Start up the library, suggesting the name of the user which was
 * passed in as the name the library should use if it needs to
 * authenticate to data sources. */
static void
startup_libuser(const char *user)
{
	struct lu_error *error = NULL;
	if (libuser != NULL) {
		shutdown_libuser();
	}
	libuser = lu_start(user, lu_user, NULL, NULL,
			   lu_prompt_console, NULL, &error);
	if (error != NULL || libuser == NULL) {
		fprintf(stderr,
			_("%s: libuser initialization error:"), progname);
	}
	if (error != NULL) {
		fprintf(stderr,
			" %s\n", lu_strerror(error));
		_exit(1);
	}
	if (libuser == NULL) {
		fprintf(stderr,
			" unknown error\n");
		_exit(1);
	}
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
	int retval = 1, i;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	const char *current = NULL;
	gboolean started = FALSE;
	if (libuser == NULL) {
		startup_libuser("root");
		started = TRUE;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		current = lu_ent_get_first_value_strdup(ent, LU_SHADOWPASSWORD);
		if (current == NULL)
			lu_ent_get_first_value_strdup(ent, LU_USERPASSWORD);
		if (current && (force == 0)) {
			/* Search for a non-locking character. */
			for (i = 0; (current[i] == '!'); i++) {
				/*nothing */
			};
			/* If the first non-locking character is the end of the
			 * string, */
			if (current[i] == '\0') {
				fprintf(stderr, "%s: %s\n", progname,
					_("Warning: unlocked password would be empty."));
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
		const char *current;

		current = lu_ent_get_first_value_strdup(ent, LU_SHADOWPASSWORD);
		if (current == NULL)
			lu_ent_get_first_value_strdup(ent, LU_USERPASSWORD);
		if (current != NULL && *current == '!')
			/* Just note this, do not abort, do not change exit
			 * code; if someone wants to use -d at all, let's not
			 * break their scripts. */
			fprintf(stderr, "%s: %s\n", progname,
				_("Note: deleting a password also unlocks the "
				  "password."));
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

static long long
ent_value_int64(struct lu_ent *ent, const char *attribute)
{
	GValueArray *values;
	GValue *value;
        value = NULL;
        values = lu_ent_get(ent, attribute);
        if (values) {
		value = g_value_array_get_nth(values, 0);
	}
	if (value) {
		if (G_VALUE_HOLDS_STRING(value)) {
			return strtoll(g_value_get_string(value), NULL, 10);
		}
	        else if (G_VALUE_HOLDS_LONG(value)) {
	                return g_value_get_long(value);
	        }
	        else if (G_VALUE_HOLDS_INT64(value)) {
	                return (long long)g_value_get_int64(value);
		}
        }
        return -1;
}

int
pwdb_display_status(const char *username)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *current;
	char *current_user;
	char *realname;
	const char *msg;
	int shadow = 1;
	time_t sp_lstchg = 0;
	long long sp_min = 0;
	long long sp_max = 0;
	long long sp_warn = 0;
	long long sp_inact= 0;
	char date[80];
	const char *status;
	struct tm tm;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		realname = lu_ent_get_first_value_strdup(ent, LU_USERNAME);
		if (realname == NULL) {
			fprintf(stderr, "%s: %s\n", progname,
				_("Corrupted passwd entry."));
			goto bail;
		}
		current = lu_ent_get_first_value_strdup(ent, LU_SHADOWPASSWORD);
		current_user = lu_ent_get_first_value_strdup(ent, LU_USERPASSWORD);
		if (current == NULL) {
			shadow = 0;
			current = current_user;
		} else {
			sp_lstchg = (time_t) ent_value_int64(ent, LU_SHADOWLASTCHANGE);
			sp_min = ent_value_int64(ent, LU_SHADOWMIN);
			sp_max = ent_value_int64(ent, LU_SHADOWMAX);
			sp_warn = ent_value_int64(ent, LU_SHADOWWARNING);
			sp_inact = ent_value_int64(ent, LU_SHADOWINACTIVE);
		}
		if (current) {
			status = "PS";
			if (strlen(current) == 0) {
				msg = _("Empty password.");
				status = "NP";
			} else if (current[0] == '!') {
				msg = _("Password locked.");
				status = "LK";
			} else if (current[0] == '$') {
				if (strncmp(current, "$1$", 3) == 0) {
					msg = _("Password set, MD5 crypt.");
				} else if (strncmp(current, "$2a$", 4) ==
					   0) {
					msg = _("Password set, blowfish crypt.");
				} else if (strncmp(current, "$5$", 3) ==
					   0) {
					msg = _("Password set, SHA256 crypt.");
				} else if (strncmp(current, "$6$", 3) ==
					   0) {
					msg = _("Password set, SHA512 crypt.");
				} else {
					msg = _("Password set, unknown crypt variant.");
				}
			} else if (strlen(current) < 11) {
				msg = _("Alternate authentication scheme in use.");
				if (current[0] == '*' || current[0] == 'x') {
					status = "LK";
				}
			} else {
				msg = _("Password set, DES crypt.");
			}
			if (shadow) {
				if (status[0] != 'N' && current_user && strlen(current_user) == 0) {
					fprintf(stderr, "%s: %s\n", progname,
						_("There is a password information set in /etc/shadow,"
						  " but the password field in /etc/passwd is empty."));
					msg = _("Empty password.");
					status = "NP";
				}
				sp_lstchg = sp_lstchg * 24L * 3600L;
				localtime_r(&sp_lstchg, &tm);
				strftime(date, sizeof(date), "%Y-%m-%d", &tm);
				printf("%s %s %s %lld %lld %lld %lld (%s)\n", realname, status,
					date, sp_min, sp_max, sp_warn, sp_inact, msg);
			} else {
				printf("%s %s (%s)\n", realname, status, msg);
			}
			g_free(current);
			if (shadow && current_user) {
				g_free(current_user);
			}
		} else {
			printf(_("No password set.\n"));
		}
		g_free(realname);
		retval = 0;
	} else {
		printf(_("Unknown user.\n"));
		retval = 2;
	}
bail:
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

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		lu_ent_set_string(ent, LU_GECOS, gecos);

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

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		lu_ent_set_string(ent, LU_LOGINSHELL, shell);

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
		  long min, long max, long warn, long inact, long lastchg)
{
	int retval = 1;
	struct lu_ent *ent;
	struct lu_error *error = NULL;

	startup_libuser(username);

	ent = lu_ent_new();
	if (lu_user_lookup_name(libuser, username, ent, &error)) {
		if (!lu_ent_get(ent, LU_SHADOWMIN) &&
		    !lu_ent_get(ent, LU_SHADOWMAX) &&
		    !lu_ent_get(ent, LU_SHADOWWARNING) &&
		    !lu_ent_get(ent, LU_SHADOWINACTIVE)) {
			fprintf(stderr, _("%s: user account has no support "
					  "for password aging.\n"), progname);
			shutdown_libuser();
			return retval;
		}

		if (min != -2)
			lu_ent_set_long(ent, LU_SHADOWMIN, min);
		if (max != -2)
			lu_ent_set_long(ent, LU_SHADOWMAX, max);
		if (warn != -2)
			lu_ent_set_long(ent, LU_SHADOWWARNING, warn);
		if (inact != -2)
			lu_ent_set_long(ent, LU_SHADOWINACTIVE, inact);
		if (lastchg != -2)
			lu_ent_set_long(ent, LU_SHADOWLASTCHANGE, lastchg);

		if (lu_user_modify(libuser, ent, &error)) {
			retval = 0;
		}
	}

	CHECK_ERROR(error);

	shutdown_libuser();
	return retval;
}
