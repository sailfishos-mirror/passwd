%if %{?WITH_SELINUX:0}%{!?WITH_SELINUX:1}
%define WITH_SELINUX 1
%endif
Summary: The passwd utility for setting/changing passwords using PAM.
Name: passwd
Version: 0.68
Release: 7 
License: BSD
Group: System Environment/Base
Source: passwd-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/passwd-root
Requires: pam >= 0.59, /etc/pam.d/system-auth
BuildPrereq: glib2-devel, libuser-devel, pam-devel

%description
The passwd package contains a system utility (passwd) which sets
and/or changes passwords, using PAM (Pluggable Authentication
Modules).

To use passwd, you should have PAM installed on your system.

%prep
%setup -q

%build
make DEBUG= RPM_OPT_FLAGS="$RPM_OPT_FLAGS" \
%if %{WITH_SELINUX}
	WITH_SELINUX=yes
%endif

%install
make install DESTDIR=$RPM_BUILD_ROOT bindir=%{_bindir} mandir=%{_mandir}
strip $RPM_BUILD_ROOT%{_bindir}/passwd
install -m 755 -d $RPM_BUILD_ROOT/etc/pam.d/
install -m 644 passwd.pamd $RPM_BUILD_ROOT/etc/pam.d/passwd

rm -f $RPM_BUILD_ROOT/%{_bindir}/{chfn,chsh}
rm -f $RPM_BUILD_ROOT/%{_mandir}/man1/{chfn,chsh}.*

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config /etc/pam.d/passwd
%attr(4511,root,root) %{_bindir}/passwd
%{_mandir}/man1/passwd.1*

%changelog
* Mon Jan 26 2004 Dan Walsh <dwalsh@redhat.com> 0.68-7
- fix is_selinux_enabled

* Fri Sep 5 2003 Dan Walsh <dwalsh@redhat.com> 0.68-6
- turn off selinux

* Fri Sep 5 2003 Dan Walsh <dwalsh@redhat.com> 0.68-5.sel
- Add SELinux support

* Mon Jul 28 2003 Dan Walsh <dwalsh@redhat.com> 0.68-4
- Add SELinux support

* Thu Feb 13 2003 Nalin Dahyabhai <nalin@redhat.com> 0.68-3
- add aging adjustment flags to passwd(1)'s synopsis, were just in the
  reference section before

* Mon Jan 27 2003 Nalin Dahyabhai <nalin@redhat.com> 0.68-2
- rebuild

* Mon Dec  9 2002 Nalin Dahyabhai <nalin@redhat.com> 0.68-1
- implement aging adjustments for pwdb

* Mon Nov 11 2002 Nalin Dahyabhai <nalin@redhat.com> 0.67-4
- modify default PAM configuration file to not specify directories, so that
  the same configuration can be used for all arches on multilib systems
- fix BuildPrereq on glib-devel to specify glib2-devel instead
- remove unpackaged files in %%install phase

* Tue May 28 2002 Nalin Dahyabhai <nalin@redhat.com> 0.67-3
- rebuild

* Mon May 20 2002 Nalin Dahyabhai <nalin@redhat.com> 0.67-2
- rebuild in new environment

* Wed Mar 13 2002 Nalin Dahyabhai <nalin@redhat.com> 0.67-1
- add the -i, -n, -w, and -x options to passwd

* Mon Mar 11 2002 Nalin Dahyabhai <nalin@redhat.com> 0.65-5
- rebuild

* Mon Feb 25 2002 Nalin Dahyabhai <nalin@redhat.com> 0.65-4
- rebuild

* Fri Feb 22 2002 Nalin Dahyabhai <nalin@redhat.com> 0.65-3
- rebuild

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
