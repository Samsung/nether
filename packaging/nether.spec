Name:           nether
Epoch:          1
Version:        0.0.1
Release:        0
Source0:        %{name}-%{version}.tar.gz
License:        Apache-2.0
Group:          Security/Other
Summary:        Daemon for enforcing network privileges
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  libnetfilter_queue-devel
Requires:       iptables

%description
This package provides a daemon used to manage zones - start, stop and switch
between them. A process from inside a zone can request a switch of context
(display, input devices) to the other zone.

%files
%manifest packaging/nether.manifest
%defattr(644,root,root,755)
%attr(755,root,root) %{_bindir}/nether
%dir /etc/nether
%config /etc/nether/nether.policy
%config /etc/nether/setrules.sh
%config /etc/nether/nether.rules
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
         -DSCRIPT_INSTALL_DIR=%{script_dir} \
         -DSYSTEMD_UNIT_DIR=%{_unitdir}
make -k %{?jobs:-j%jobs}

%install
%make_install

%clean
rm -rf %{buildroot}

%post
# Refresh systemd services list after installation
if [ $1 == 1 ]; then
    systemctl daemon-reload || :
fi
# set needed caps on the binary to allow restart without loosing them
setcap CAP_SYS_ADMIN,CAP_MAC_OVERRIDE+ei %{_bindir}/nether

%preun
# Stop the service before uninstall
if [ $1 == 0 ]; then
     systemctl stop nether.service || :
fi

%postun
# Refresh systemd services list after uninstall/upgrade
systemctl daemon-reload || :
