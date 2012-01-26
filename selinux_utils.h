#ifndef __RH_SELINUX_UTILS_H
#define __RH_SELINUX_UTILS_H
extern void selinux_init(int auditfd);
extern int selinux_check_root(void);
#endif
