/*
 * Copyright Red Hat, Inc., 2003,2004.
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

/* Written by Daniel Walsh <dwalsh@redhat.com> */

#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <selinux/context.h>
#include "selinux_utils.h"

int
check_selinux_access(const char *change_user, int change_uid, unsigned int access)
{
	int status = -1;
	security_context_t user_context;
	const char *user;

	if (security_getenforce() == 0) {
		status = 0;
	} else {
		if (getprevcon(&user_context) == 0) {
			context_t c;
			c = context_new(user_context);
			user = context_user_get(c);
			if (change_uid != 0 && strcmp(change_user, user) == 0) {
				status = 0;
			} else {
				struct av_decision avd;
				int retval;
				retval = security_compute_av(user_context,
							     user_context,
							     SECCLASS_PASSWD,
							     access,
							     &avd);
				if ((retval == 0) && 
				    ((access & avd.allowed) == access)) {
					status = 0;
				}
			}
			context_free(c);
			freecon(user_context);
		}
	}
	return status;
}
