# $Id$
# openSUSE and fedora RPM spec for digup by Timo Bingmann

Summary: Tool to read, verify and update MD5 or SHA digest files
Name: digup
Version: 0.6.40
Release: 1%{?dist}
Group: Applications/System
License: GPL
Packager: Timo Bingmann <repo@idlebox.net>
URL: http://idlebox.net/2009/digup/
Source: http://idlebox.net/2009/digup/digup-%{version}.tar.bz2
BuildRequires: gcc
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
digup is a tool to update md5sum or shasum digest files. It will read
existing digest files, check the current directory for new, updated,
modified, renamed or deleted files and query the user with a summary
of changes. After reviewing the updates, they can be written back to
the digest file.

%prep
%setup -q

%build
%configure --enable-optimize
make %{?_smp_mflags}
make %{?_smp_mflags} check

%install
make install-strip DESTDIR=%{buildroot}

%clean
/bin/rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_bindir}/digup
%{_mandir}/man1/digup.1.gz
