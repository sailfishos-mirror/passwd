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

#include "selinux_utils.h"
#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>
#include <selinux/avc.h>
#include <libaudit.h>
#include <unistd.h>
#include <limits.h>

/* FD to send audit messages to */
static int audit_fd = -1;

/* log_callback stolen from dbus */
static int
log_callback (int type, const char *fmt, ...) 
{
  va_list ap;

  (void)type;

  va_start(ap, fmt);

  if (audit_fd >= 0)
  {
	  char buf[PATH_MAX*2];
    
	  vsnprintf(buf, sizeof(buf), fmt, ap);
	  audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC, buf, NULL, NULL,
				     NULL, 0);
	  va_end(ap);
	  return 0;
  }
  
  vsyslog (LOG_USER | LOG_INFO, fmt, ap);
  va_end(ap);
  return 0;
}
int selinux_check_root(void) {
	int status = -1;
	security_context_t user_context;

	if (getuid() != 0) return 0;
	if (is_selinux_enabled() == 0) return 0;
	if ((status = getprevcon(&user_context)) < 0) return status;

	status = selinux_check_access(user_context, user_context, "passwd", "passwd", NULL);

	freecon(user_context);

	return status;
}

void selinux_init(int fd) {
	if (is_selinux_enabled() > 0) {
		/* initialize audit log */

		audit_fd = fd;

		/* setup callbacks */
		selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback) &log_callback);
	}
}
