
#include <stdio.h>

#include "version.h"

#include "date.h"

extern char *progname;

void version(void)
{
    printf("%s: PAM + PWBD Applications, %s, Cristian Gafton <gafton@redhat.com>\n",
	   progname, version_date);
}
