# spec file for package aziot-identity-service
#
# Copyright (c) Microsoft. All rights reserved.

Name: aziot-identity-service
Version: @version@
Release: @release@
Summary: Azure IoT Identity Service and related services
License: MIT
URL: https://github.com/azure/iot-identity-service
Source: aziot-identity-service-%{version}-%{release}.tar.gz

BuildRequires: clang
BuildRequires: gcc
BuildRequires: llvm-devel
BuildRequires: make
BuildRequires: openssl-devel
BuildRequires: pkgconfig
# Required for %{_unitdir} to be defined, as described in https://fedoraproject.org/wiki/Packaging:Systemd
BuildRequires: systemd

%description
This package contains the Azure IoT device runtime, comprised of the following services:

- aziot-identityd - The Azure IoT Identity Service
- aziot-certd - The Azure IoT Certificates Service
- aziot-keyd - The Azure IoT Keys Service

This package also contains the following libraries:

- libaziot_keys.so - The library used by the Keys Service to communicate with HSMs for key operations.
- <openssl engines directory>/openssl/engines/libaziot_keys.so - An openssl engine that can be used to work with asymmetric keys managed by the Azure IoT Keys Service.


%package devel

Summary: Development files for Azure IoT Identity Service and related services

%description devel
This package contains development files for the Azure IoT device runtime.


%prep

%setup -q


%build

# Nothing to do here.


%install

# https://docs.fedoraproject.org/en-US/packaging-guidelines/RPMMacros/#_macros_for_paths_set_and_used_by_build_systems
#
# Yes, docdir is different in that it includes the name of the package, whereas others like includedir and libexecdir do not
# and the invocation of `install` is expected to append the package name manually.

make -j \
    DESTDIR=%{buildroot} \
    bindir=%{_bindir} \
    docdir=%{_docdir}/%{name} \
    includedir=%{_includedir} \
    libdir=%{_libdir} \
    libexecdir=%{_libexecdir} \
    localstatedir=%{_localstatedir} \
    sysconfdir=%{_sysconfdir} \
    unitdir=%{_unitdir} \
    OPENSSL_ENGINES_DIR=/usr/lib64/openssl/engines \
    RELEASE=1 \
    V=1 \
    SOCKET_ACTIVATION_SUPPORTED=0 \
    install-rpm

%pre

# For each of CS, IS, KS: create group, create user, create home directory (in case user already exists from a previous install
# but the user deleted the directory manually)

if ! %{_bindir}/getent group aziotks >/dev/null; then
    %{_sbindir}/groupadd -r aziotks
fi
if ! %{_bindir}/getent passwd aziotks >/dev/null; then
    %{_sbindir}/useradd -r -g aziotks -c 'aziot-keyd user' -s /sbin/nologin -d /var/lib/aziot/keyd aziotks
fi

if ! %{_bindir}/getent group aziotcs >/dev/null; then
    %{_sbindir}/groupadd -r aziotcs
fi
if ! %{_bindir}/getent passwd aziotcs >/dev/null; then
    %{_sbindir}/useradd -r -g aziotcs -c 'aziot-certd user' -s /sbin/nologin -d /var/lib/aziot/certd aziotcs
    %{_sbindir}/usermod -aG aziotks aziotcs
fi

if ! %{_bindir}/getent group aziotid >/dev/null; then
    %{_sbindir}/groupadd -r aziotid
fi
if ! %{_bindir}/getent passwd aziotid >/dev/null; then
    %{_sbindir}/useradd -r -g aziotid -c 'aziot-identityd user' -s /sbin/nologin -d /var/lib/aziot/identityd aziotid
    %{_sbindir}/usermod -aG aziotcs aziotid
    %{_sbindir}/usermod -aG aziotks aziotid
fi


%post


%postun


%files
# Service binaries
%{_libexecdir}/%{name}/aziot-certd
%{_libexecdir}/%{name}/aziot-identityd
%{_libexecdir}/%{name}/aziot-keyd

# libaziot-keys
%{_libdir}/libaziot_keys.so

# libaziot-key-openssl-engine-shared
%{_libdir}/openssl/engines/libaziot_keys.so

# Default configs
%attr(400, aziotcs, aziotcs) %{_sysconfdir}/aziot/certd/config.toml.default
%attr(400, aziotid, aziotid) %{_sysconfdir}/aziot/identityd/config.toml.default
%attr(400, aziotks, aziotks) %{_sysconfdir}/aziot/keyd/config.toml.default

# Home directories
%attr(-, aziotcs, aziotcs) %dir /var/lib/aziot/certd
%attr(-, aziotid, aziotid) %dir /var/lib/aziot/identityd
%attr(-, aziotks, aziotks) %dir /var/lib/aziot/keyd

# Systemd services
%{_unitdir}/aziot-certd.service
%{_unitdir}/aziot-identityd.service
%{_unitdir}/aziot-keyd.service

# Sockets (no systemd socket activation on CentOS)
%attr(660, aziotcs, aziotcs) /var/lib/aziot/certd.sock
%attr(660, aziotid, aziotid) /var/lib/aziot/identityd.sock
%attr(660, aziotks, aziotks) /var/lib/aziot/keyd.sock

%doc README.md
%doc THIRD-PARTY-NOTICES
%license LICENSE


%files devel
%{_includedir}/%{name}/aziot-keys.h
%license LICENSE


%changelog
