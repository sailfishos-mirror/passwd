/*
 * PWDB.C
 *
 * Some wrapper functions for libpwdb interface
 *
 * Cristian Gafton <gafton@redhat.com>
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

int pwdb_unlock_password(const char *username)
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
	pwdb_delete(&_pwdb);
	pwdb_end();
	return 0;
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
