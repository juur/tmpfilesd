Name:		tmpfilesd
Version:	1.0
Release:	1%{?dist}
Summary:	%{name}

License:	BSD
Source0:	%{name}-%{version}.tar.xz
Conflicts:	systemd

%description
%{name}

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/tmpfiles.d
mkdir -p %{buildroot}%{_prefix}/lib/tmpfiles.d
%make_install


%files
%defattr(-,root,root,-)
%{_bindir}/*
%dir %{_sysconfdir}/tmpfiles.d/
%{_prefix}/lib/tmpfiles.d/*
