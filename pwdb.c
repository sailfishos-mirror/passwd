/*
 * PWDB.C
 *
 * Some wrapper functions for libpwdb interface
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

#include "pwdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <pwdb/pwdb_public.h>
extern const char *progname;

#define CHECK_ERROR(x)     if (x != PWDB_SUCCESS) { \
 	fprintf(stderr, "%s: Error %d - %s.\n", \
		progname, __LINE__, pwdb_strerror(x)); /* that is an old trick... */ \
	if (_pwdb != (struct pwdb *)NULL) \
	    pwdb_delete(&_pwdb); \
	pwdb_end(); \
	return -1; \
    }

int pwdb_lock_password(const char *username)
{
    const struct pwdb *_pwdb = NULL;
    const struct pwdb_entry *_pwe = NULL;
    char *new_pass, *t;
    int retval, flags;

    retval = pwdb_start();
    if (retval != PWDB_SUCCESS)
	return -1;
    retval=pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_get_entry(_pwdb, "passwd", &_pwe);
    if (_pwe == (struct pwdb_entry *)NULL) {
	/* this user does not have a password set */
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    
    new_pass = alloca(_pwe->length+1);
    t = (char *)_pwe->value;
    if (*t == '!') {
	/* already locked... */
	return 0;
    }
    snprintf(new_pass, _pwe->length+1, "!%s", t);
    retval = pwdb_set_entry(_pwdb, "passwd", new_pass,
			    _pwe->length+1, NULL, NULL, 0);
    CHECK_ERROR(retval);

    retval = pwdb_entry_delete(&_pwe);
    CHECK_ERROR(retval);
    
    retval=pwdb_flags("user", _pwdb->source, &flags);
    CHECK_ERROR(retval);    
    if ( flags & PWDB_F_NOUPDATE ) {
	fprintf(stderr, "%s: insufficient privilege to complete operation\n",
		progname);
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    retval=pwdb_replace("user", _pwdb->source, username,
			PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval);
    pwdb_end();
    return retval;
}

int pwdb_unlock_password(const char *username, int force)
{
    const struct pwdb *_pwdb = NULL;
    const struct pwdb_entry *_pwe = NULL;
    char *t;
    int retval, flags;

    retval = pwdb_start();
    if (retval != PWDB_SUCCESS)
	return -1;
    retval=pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_get_entry(_pwdb, "passwd", &_pwe);
    CHECK_ERROR(retval);

    t = (char *)_pwe->value;
    if (*t != '!') {
	/* already unlocked... */
	pwdb_delete(&_pwdb);
	pwdb_end();
	return 0;
    } else if (_pwe->length <= 2) {
	/* avoid leaving empty passwords */
	if (force) { 
	    t++; /* The user really knows what is going on... */
	} else {
	    fprintf(stderr, "Warning: unlocked password for %s is the empty string.\n"
		    "Use the -f flag to force the creation of a passwordless account.\n",
		    username);
	    pwdb_delete(&_pwdb);
	    pwdb_end();
	    return -2;
	}
    } else {
	/* okay, we need to "unlock" it */
	t++;
    }
    retval = pwdb_set_entry(_pwdb, "passwd", t,
			    _pwe->length-1, NULL, NULL, 0);
    CHECK_ERROR(retval);

    retval = pwdb_entry_delete(&_pwe);
    CHECK_ERROR(retval);
    
    retval=pwdb_flags("user", _pwdb->source, &flags);
    CHECK_ERROR(retval);    
    if ( flags & PWDB_F_NOUPDATE ) {
	fprintf(stderr, "%s: insufficient privilege to complete operation\n",
		progname);
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    retval=pwdb_replace("user", _pwdb->source, username,
			PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval);
    pwdb_end();
    return retval;
}

int pwdb_clear_password(const char *username)
{
    const struct pwdb *_pwdb = NULL;
    int retval, flags;

    retval = pwdb_start();
    if (retval != PWDB_SUCCESS)
	return -1;
    retval=pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);

    retval=pwdb_flags("user", _pwdb->source, &flags);
    CHECK_ERROR(retval);    
    if ( flags & PWDB_F_NOUPDATE ) {
	fprintf(stderr, "%s: insufficient privilege to complete operation\n",
		progname);
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    retval = pwdb_set_entry(_pwdb, "passwd", "", 1, NULL, NULL, 0);
    CHECK_ERROR(retval);
    retval=pwdb_replace("user", _pwdb->source, username,
			PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval);
    pwdb_end();
    return retval;
}

int pwdb_display_status(const char *username)
{
    const struct pwdb *_pwdb = NULL;
    const struct pwdb_entry *_pwe = NULL;
    char *t;
    int retval;

    retval = pwdb_start();
    if (retval != PWDB_SUCCESS)
	return -1;
    retval=pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_get_entry(_pwdb, "passwd", &_pwe);
    if (_pwe == (struct pwdb_entry *)NULL) {
	/* this user does not have a password set */
	printf("No Password set.\n");
	pwdb_delete(&_pwdb);
	pwdb_end();
	return 0;
    }
    
    t = (char *)_pwe->value;
    if (strlen(t) == 0) {
	printf("Empty password.\n");
	pwdb_delete(&_pwdb);
	pwdb_end();
	return 0;
    }

    switch (*t) {
	case '!':
	    printf("Locked password.\n");
	    break;
	case '$':
	    if (strncmp(t, "$1$", 3) == 0) {
		printf("Password set, MD5 encryption\n");
	    } else {
		printf("Password set, unknown encryption\n");
	    }
	    break;
	default:
	    printf("Password set, DES encription\n");
    }
    retval = pwdb_entry_delete(&_pwe);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval);
    pwdb_end();
    return 0;
}

int pwdb_update_gecos(const char *username, const char *gecos)
{
    const struct pwdb *_pwdb = NULL;
    int retval, flags;
    
    /* Now update the user entry */
    pwdb_start();
    retval = pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    
    retval=pwdb_flags("user", _pwdb->source, &flags);
    CHECK_ERROR(retval);    
    if ( flags & PWDB_F_NOUPDATE ) {
	fprintf(stderr, "%s: insufficient privilege to complete operation\n",
		progname);
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    retval = pwdb_set_entry(_pwdb, "gecos", gecos, 1+strlen(gecos),
			    NULL, NULL, 0);
    CHECK_ERROR(retval);
    retval = pwdb_replace("user", _pwdb->source, username,
			  PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval)
    pwdb_end();
    return 0;
}

int pwdb_update_shell(const char *username, const char *shell)
{
    const struct pwdb *_pwdb = NULL;
    int retval, flags;
    
    /* Now update the user entry */
    pwdb_start();
    retval = pwdb_locate("user", PWDB_DEFAULT, username, PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    
    retval=pwdb_flags("user", _pwdb->source, &flags);
    CHECK_ERROR(retval);    
    if ( flags & PWDB_F_NOUPDATE ) {
	fprintf(stderr, "%s: insufficient privilege to complete operation\n",
		progname);
	pwdb_delete(&_pwdb);
	pwdb_end();
	return -1;
    }
    retval = pwdb_set_entry(_pwdb, "shell", shell, 1+strlen(shell),
			    NULL, NULL, 0);
    CHECK_ERROR(retval);
    retval = pwdb_replace("user", _pwdb->source, username,
			  PWDB_ID_UNKNOWN, &_pwdb);
    CHECK_ERROR(retval);
    retval = pwdb_delete(&_pwdb);
    CHECK_ERROR(retval)
    pwdb_end();
    return 0;
}
