#
# $Id$
#

BACKLIB=libuser

ifeq (libuser,$(BACKLIB))
CFLAGS  = $(shell pkg-config --cflags libuser)
LDFLAGS = $(shell pkg-config --libs   libuser)
DEFS = -DLIBUSER
endif

ifeq (pwdb,$(BACKLIB))
CFLAGS =
LDFLAGS = -lpwdb
DEFS = -DPWDB
endif

CC	= gcc
DEBUG	= -g
CFLAGS	+= $(RPM_OPT_FLAGS) -Wall -D_GNU_SOURCE $(DEBUG) $(DEFS)
LDFLAGS	+= -ldl -lpam -lpam_misc
PROGS	= passwd chfn chsh
POPT	= -lpopt

PROJECT	= passwd

VERSION = $(shell awk '/^Version:/ { print $$2 }' $(PROJECT).spec)
RELEASE = $(shell awk '/^Release:/ { print $$2 }' $(PROJECT).spec)
CVSTAG = r$(subst .,-,$(VERSION)-$(RELEASE))

bindir=/usr/bin
mandir=/usr/man

all: date.h $(PROGS) pwdstat
#	chmod 4555 $(PROGS)

%.o : %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

passwd: passwd.o libuser.o pwdb.o
	$(CC) $(LDFLAGS) -o $@ $^ $(POPT)

chfn: chfn.o libuser.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

chsh: chsh.o libuser.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

pwdstat: pwdstat.o
	$(CC) $(LDFLAGS) -o $@ $^

install: all
	if [ ! -d $(DESTDIR)$(bindir) ] ; then mkdir -p $(DESTDIR)$(bindir) ; fi
	if [ ! -d $(DESTDIR)$(mandir)/man1 ] ; then mkdir -p $(DESTDIR)$(mandir)/man1 ; fi
	install -m 4555 $(PROGS) $(DESTDIR)$(bindir)/
	install -m 644 $(wildcard *.1) $(DESTDIR)$(mandir)/man1/

clean:
	rm -f *.o *~ $(PROGS) date.h
	rm -f $(PROJECT)-*.tar.gz

version.o: date.h

date.h: 
	echo "static char version_date[] = \"" `date +%D` "\";" > date.h

tag:
	cvs tag -cR $(CVSTAG) .

force-tag:
	cvs tag -cFR $(CVSTAG) .

archive:
	@rm -rf /tmp/$(PROJECT)-$(VERSION) /tmp/password
	@cd /tmp; cvs export -r$(CVSTAG) password
	@mv /tmp/password /tmp/$(PROJECT)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROJECT)-$(VERSION)-$(RELEASE).tar.gz $(PROJECT)-$(VERSION)
	@rm -rf /tmp/$(PROJECT)-$(VERSION)
	@echo "The archive is in $(PROJECT)-$(VERSION)-$(RELEASE).tar.gz"
