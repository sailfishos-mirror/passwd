#
# $Id$
#

CC	= gcc
DEBUG	= -g
CFLAGS	= $(RPM_OPT_FLAGS) -Wall -D_GNU_SOURCE $(DEBUG)
LDFLAGS	= -ldl -lpam -lpam_misc -lpwdb
PROGS	= passwd chfn chsh
POPT	= -lpopt

PROJECT	= passwd

VERSION = $(shell awk '/^Version:/ { print $$2 }' $(PROJECT).spec)
CVSTAG = r$(subst .,-,$(VERSION))

bindir=/usr/bin
mandir=/usr/man
DESTDIR	= $(TOP_DIR)$(bindir)
MANDIR	= $(TOP_DIR)$(mandir)

all: date.h $(PROGS) pwdstat
#	chmod 4555 $(PROGS)

%.o : %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

passwd: passwd.o pwdb.o
	$(CC) $(LDFLAGS) -o $@ $^ $(POPT)

chfn: chfn.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

chsh: chsh.o pwdb.o version.o
	$(CC) $(LDFLAGS) -o $@ $^

pwdstat: pwdstat.o
	$(CC) $(LDFLAGS) -o $@ $^

install: all
	if [ ! -d $(DESTDIR) ] ; then mkdir -p $(DESTDIR) ; fi
	install -m 4555 $(PROGS) $(DESTDIR)
	if [ ! -d $(MANDIR) ] ; then mkdir -p $(MANDIR) ; fi
	if [ ! -d $(MANDIR)/man1 ] ; then mkdir -p $(MANDIR)/man1 ; fi
	install -m 644 $(wildcard *.1) $(MANDIR)/man1

clean:
	rm -f *.o *~ $(PROGS) date.h
	rm -f $(PROJECT)-*.tar.gz

version.o: date.h

date.h: 
	echo "static char version_date[] = \"" `date +%D` "\";" > date.h

archive:
	cvs tag -F $(CVSTAG) .
	@rm -rf /tmp/$(PROJECT)-$(VERSION) /tmp/password
	@cd /tmp; cvs export -r$(CVSTAG) password
	@mv /tmp/password /tmp/$(PROJECT)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROJECT)-$(VERSION).tar.gz $(PROJECT)-$(VERSION)
	@rm -rf /tmp/$(PROJECT)-$(VERSION)
	@echo "The archive is in $(PROJECT)-$(VERSION).tar.gz"
