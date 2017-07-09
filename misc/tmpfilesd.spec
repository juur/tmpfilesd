Name:		tmpfilesd
Version:	1.0
Release:	1%{?dist}
Summary:	%{name}

License:	BSD
Source0:	%{name}-%{version}.tar.xz
Conflicts:	systemd

%package sysvinit
Summary:	%{name} sysvinit scripts
Requires:	initscripts 
Requires:	%{name}
BuildArch:	noarch

%description
%{name}

%description sysvinit
%{name} sysv init scripts

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/tmpfiles.d
mkdir -p %{buildroot}%{_prefix}/lib/tmpfiles.d
mkdir -p %{buildroot}%{_mandir}/man8
%make_install

mkdir -p %{buildroot}%{_initrddir}
install -T -m 755 misc/%{name}.init %{buildroot}%{_initrddir}/%{name}


%files
%defattr(-,root,root,-)
%{_bindir}/*
%dir %{_sysconfdir}/tmpfiles.d/
%{_prefix}/lib/tmpfiles.d/*
%{_mandir}/*/*.*
%doc COPYING README.md

%files sysvinit
%defattr(-,root,root,-)
%{_initrddir}/%{name}
