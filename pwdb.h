/*
 * PWDB.H
 * ======
 *
 * Prototypes for the wrapper functions for libpwdb
 */

#ifndef _RH_PWDB_H_
#define _RH_PWDB_H_

int pwdb_lock_password(const char *username);
int pwdb_unlock_password(const char *username);
int pwdb_clear_password(const char *username);
int pwdb_display_status(const char *username);
int pwdb_update_gecos(const char *username, const char *gecos);
int pwdb_update_shell(const char *username, const char *shell);

#endif /* _RH_PWDB_H_ */

