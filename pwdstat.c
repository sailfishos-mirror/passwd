/*
 * Written by Cristian Gafton <gafton@redhat.com>
 */

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pwd.h>
#include <getopt.h>

char *username = NULL;		/* username we are changing the password for */
char *password = NULL;		/* password we are changing the password to */

/* a dummy coversation function */
static int
dummy_conv(int num_msg,
	   const struct pam_message **msg,
	   struct pam_response **resp, void *appdata_ptr)
{
	int i;
	struct pam_response *response = NULL;

	(void)appdata_ptr;

	response = malloc(sizeof(struct pam_response) * num_msg);

	if (response == (struct pam_response *) 0)
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		response[i].resp_retcode = PAM_SUCCESS;

		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			response[i].resp = username;
			break;

		case PAM_PROMPT_ECHO_OFF:
			response[i].resp = password;
			break;

		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			/* ignore it, but pam still wants a NULL response... */
			response[i].resp = NULL;
			break;

		default:
			/* Must be an error of some sort... */
			free(response);
			return PAM_CONV_ERR;
		}
	}

	*resp = response;
	return PAM_SUCCESS;
}


/* conversation function & corresponding structure */
static struct pam_conv conv = {
	&dummy_conv,
	NULL
};

int
main(int argc, char *const argv[])
{
	int retval;
	pam_handle_t *pamh = NULL;

	/* XXX; expand me:
	 *
	 * here you should obtains somehow the username and password and
	 * set the global variables
	 */
	(void)argc;
	(void)argv;
	assert(username != NULL);
	assert(password != NULL);

	retval = pam_start("passwd", username, &conv, &pamh);
	while (retval == PAM_SUCCESS) {	/* use loop to avoid goto... */

		retval = pam_chauthtok(pamh, 0);
		if (retval != PAM_SUCCESS)
			break;
		/* all done */
		retval = pam_end(pamh, PAM_SUCCESS);
		if (retval != PAM_SUCCESS)
			break;
		/* quit gracefully */
		exit(0);
	}

	if (retval != PAM_SUCCESS)
		fprintf(stderr, "changing password: %s\n",
			pam_strerror(pamh, retval));

	if (pamh != NULL) {
		(void) pam_end(pamh, PAM_SUCCESS);
		pamh = NULL;
	}

	exit(1);
}
