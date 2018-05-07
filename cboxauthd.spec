# 
# cboxauthd spec file
#

Name: cboxauthd
Summary: Authentication daemon for CERNBox.
Version: 1.2.1
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides a golang webserver that provides an authentication service for web clients.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/cboxauthd
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/cboxauthd
install -m 755 cboxauthd	     %buildroot/usr/local/bin/cboxauthd
install -m 644 cboxauthd.service    %buildroot/usr/lib/systemd/system/cboxauthd.service
install -m 644 cboxauthd.yaml       %buildroot/etc/cboxauthd/cboxauthd.yaml
install -m 644 cboxauthd.logrotate  %buildroot/etc/logrotate.d/cboxauthd

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/cboxauthd
/etc/logrotate.d/cboxauthd
/var/log/cboxauthd
/usr/lib/systemd/system/cboxauthd.service
/usr/local/bin/*
%config(noreplace) /etc/cboxauthd/cboxauthd.yaml


%changelog
* Mon May 07 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.2.1
- Fix clear cache handler
* Sun May 06 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.2.0
- Remove dumper handler and modify expire and clear handlers 
* Wed May 02 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.1.3
- Replace hashing algo: md5 to sha256 with salt
* Fri Apr 12 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.1.2
* Tue Apr 4 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.1.1
* Wed Dec 13 2017 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.1
- Fix expiration time
* Thu Nov 28 2017 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.0
- v1.0.0

