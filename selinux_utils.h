#ifndef __RH_SELINUX_UTILS_H
#define __RH_SELINUX_UTILS_H
int check_selinux_access(const char *change_user, int change_uid, unsigned int access);
#endif
