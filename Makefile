#
# $Id$
#

CC	= gcc
DEBUG	= -g
CFLAGS	= -Wall -pedantic -D_GNU_SOURCE $(DEBUG)
LDFLAGS	= -ldl -lpam -lpam_misc -lpwdb
PROGS	= passwd chfn chsh

DESTDIR	= $(TOP_DIR)/usr/bin

all: date.h $(PROGS)
#	chmod 4555 $(PROGS)

%.o : %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

passwd: passwd.o pwdb.o
	$(CC) $(LDFLAGS) -o $@ $^

chfn: chfn.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

chsh: chsh.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

install: all
	if [ ! -d $(DESTDIR) ] ; then mkdir -p $(DESTDIR) ; fi
	install -m 4555 -o root -g root $(PROGS) $(DESTDIR)

clean:
	rm -f *.o *~ $(PROGS) date.h

version.o: date.h

date.h: 
	echo "static char version_date[] = \"" `date +%D` "\";" > date.h

