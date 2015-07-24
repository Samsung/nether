Name:		nether
Version:	0.0.1
Release:	0
Source0:	%{name}-%{version}.tar.gz
License:	Apache-2.0
Group:		Security/Other
Summary:	Daemon for enforcing network privileges
BuildRequires:	cmake
BuildRequires:	libnetfilter_queue-devel
BuildRequires:	pkgconfig(cynara-client-async)
Requires:	iptables

%description
This is a network privilege enforcing service.

%files
%defattr(644,root,root,755)
%caps(cap_sys_admin,cap_mac_override=ei) %attr(755,root,root) %{_bindir}/nether
%dir %{_sysconfdir}/nether
%config %{_sysconfdir}/nether/nether.policy
%config %{_sysconfdir}/nether/nether.rules
%{_unitdir}/nether.service
%{_unitdir}/multi-user.target.wants/nether.service
%prep
%setup -q

%build
%{!?build_type:%define build_type "RELEASE"}

%if %{build_type} == "DEBUG" || %{build_type} == "PROFILING" || %{build_type} == "CCOV"
	CFLAGS="$CFLAGS -Wp,-U_FORTIFY_SOURCE"
	CXXFLAGS="$CXXFLAGS -Wp,-U_FORTIFY_SOURCE"
%endif

%cmake . -DVERSION=%{version} \
	-DCMAKE_BUILD_TYPE=%{build_type} \
	-DSYSTEMD_UNIT_DIR=%{_unitdir} \
	-DBIN_INSTALL_DIR=%{_bindir} \
	-DSYSCONF_INSTALL_DIR=%{_sysconfdir}

make %{?_smp_mflags}

%install
%make_install

%clean
rm -rf %{buildroot}

%post
# Refresh systemd services list after installation
systemctl daemon-reload || :
if [ $1 == 1 ]; then
	systemctl start nether.service || :
fi
if [ $1 == 2 ]; then
	systemct restart nether.service || :
fi

%preun
# Stop the service before uninstall
if [ $1 == 0 ]; then
	systemctl stop nether.service || :
fi

%postun
# Refresh systemd services list after uninstall/upgrade
systemctl daemon-reload || :
