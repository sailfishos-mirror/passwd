Summary: The passwd utility for setting/changing passwords using PAM.
Name: passwd
Version: 0.65
Release: 2
License: BSD
Group: System Environment/Base
Source: passwd-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/passwd-root
Requires: pam >= 0.59, /etc/pam.d/system-auth
BuildPrereq: glib-devel, libuser-devel, pam-devel

%description
The passwd package contains a system utility (passwd) which sets
and/or changes passwords, using PAM (Pluggable Authentication
Modules).

To use passwd, you should have PAM installed on your system.

%prep
%setup -q

%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
make install DESTDIR=$RPM_BUILD_ROOT bindir=%{_bindir} mandir=%{_mandir}
strip $RPM_BUILD_ROOT%{_bindir}/passwd
install -m 755 -d $RPM_BUILD_ROOT/etc/pam.d/
install -m 644 passwd.pamd $RPM_BUILD_ROOT/etc/pam.d/passwd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config /etc/pam.d/passwd
%attr(4511,root,root) %{_bindir}/passwd
%{_mandir}/man1/passwd.1*

%changelog
* Thu Jan 31 2002 Nalin Dahyabhai <nalin@redhat.com> 0.65-2
- rebuild to get dependencies right

* Tue Jan 29 2002 Nalin Dahyabhai <nalin@redhat.com> 0.65-1
- change dependency from pwdb to libuser

* Fri Jan 25 2002 Nalin Dahyabhai <nalin@redhat.com> 0.64.1-9
- rebuild

* Thu Aug 30 2001 Nalin Dahyabhai <nalin@redhat.com> 0.64.1-8
- man page fix (-r is the opposite of -l, not --stdin, which precedes it)
  from Felipe Gustavo de Almeida

* Mon Aug  6 2001 Nalin Dahyabhai <nalin@redhat.com> 0.64.1-7
- fix unguarded printf() (noted by Chris Evans)
- add missing build dependency on pwdb and pam-devel (#49550)

* Sun Jun 24 2001 Elliot Lee <sopwith@redhat.com>
- Bump release + rebuild.

* Wed Jul 12 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild

* Mon Jun  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- move man pages to %{_mandir}

* Thu Jun  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- modify PAM setup to use system-auth
- modify for building as non-root users

* Mon Feb  7 2000 Bill Nottingham <notting@redhat.com>
- fix manpage links

* Fri Feb 04 2000 Nalin Dahyabhai <nalin@redhat.com>
- document --stdin in man page
- fix for gzipped man pages

* Sat Apr 10 1999 Cristian Gafton <gafton@redhat.com>
- first build from the new source code base.
