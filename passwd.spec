Summary: The passwd utility for setting/changing passwords using PAM.
Name: passwd
Version: 0.61
Release: 1
Copyright: BSD
Group: System Environment/Base
Source: passwd-%{version}.tar.gz
Buildroot: /var/tmp/passwd-root
Requires: pam >= 0.59
Requires: pwdb >= 0.58

%description
The passwd package contains a system utility (passwd) which
sets and/or changes passwords, using PAM (Pluggable Authentication
Modules).

To use passwd, you should have PAM installed on your system.

%prep
%setup -q

%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
mkdir -p $RPM_BUILD_ROOT/usr/{bin,man/man1}
make install TOP_DIR=$RPM_BUILD_ROOT
strip $RPM_BUILD_ROOT/usr/bin/passwd
mkdir -p $RPM_BUILD_ROOT/etc/pam.d/
install -m 644 passwd.pamd $RPM_BUILD_ROOT/etc/pam.d/passwd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config /etc/pam.d/passwd
%attr(4511,root,root) /usr/bin/passwd
/usr/man/man1/passwd.1

%changelog
* Sat Apr 10 1999 Cristian Gafton <gafton@redhat.com>
- first build from the new source code base.
