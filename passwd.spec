Summary: The passwd utility for setting/changing passwords using PAM.
Name: passwd
Version: 0.64.1
Release: 3
Copyright: BSD
Group: System Environment/Base
Source: passwd-%{version}.tar.gz
Buildroot: %{_tmppath}/passwd-root
Requires: pam >= 0.59, /etc/pam.d/system-auth
Requires: pwdb >= 0.58

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
mkdir -p $RPM_BUILD_ROOT{%{_bindir},%{_mandir}/man1}
make install TOP_DIR=$RPM_BUILD_ROOT bindir=%{_bindir} mandir=%{_mandir}
strip $RPM_BUILD_ROOT%{_bindir}/passwd
mkdir -p $RPM_BUILD_ROOT/etc/pam.d/
install -m 644 passwd.pamd $RPM_BUILD_ROOT/etc/pam.d/passwd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config /etc/pam.d/passwd
%attr(4511,root,root) %{_bindir}/passwd
%{_mandir}/man1/passwd.1*

%changelog
* The next time we build passwd.
- fix unguarded printf() (note from Chris Evans)

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
