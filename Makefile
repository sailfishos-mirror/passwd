#
# $Id$
#

CC	= gcc
DEBUG	= -g
CFLAGS	= $(RPM_OPT_FLAGS) -Wall -pedantic -D_GNU_SOURCE $(DEBUG)
LDFLAGS	= -ldl -lpam -lpam_misc -lpwdb
PROGS	= passwd chfn chsh

PROJECT	= password

VERSION = $(shell awk '/^Version:/ { print $$2 }' $(PROJECT).spec)
CVSTAG = r$(subst .,-,$(VERSION))

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
	rm -f $(PROJECT)-*.tar.gz

version.o: date.h

date.h: 
	echo "static char version_date[] = \"" `date +%D` "\";" > date.h

archive:
	cvs tag -F $(CVSTAG) .
	@rm -rf /tmp/$(PROJECT)-$(VERSION) /tmp/$(PROJECT)
	@cd /tmp; cvs export -r$(CVSTAG) $(PROJECT)
	@mv /tmp/$(PROJECT) /tmp/$(PROJECT)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROJECT)-$(VERSION).tar.gz $(PROJECT)-$(VERSION)
	@rm -rf /tmp/$(PROJECT)-$(VERSION)
	@echo "The archive is in $(PROJECT)-$(VERSION).tar.gz"
