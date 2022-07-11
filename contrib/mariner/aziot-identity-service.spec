# spec file for package aziot-identity-service
#
# Copyright (c) Microsoft. All rights reserved.


# TODO:
# Building debuginfo package fails due to https://github.com/rust-lang/rust/issues/82006
# Remove this once that's fixed.
%define debug_package %{nil}


Name: aziot-identity-service
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
Summary: Azure IoT Identity Service and related services
License: MIT
URL: https://github.com/azure/iot-identity-service
Source:  %{name}-%{version}.tar.gz
Source1: rust-bindgen-@@BINDGEN_VERSION@@.tar.gz
Source2: cbindgen-@@CBINDGEN_VERSION@@.tar.gz
Source3: rust.tar.gz

Conflicts: iotedge, libiothsm-std

BuildRequires: clang-devel
BuildRequires: cmake
BuildRequires: gcc
BuildRequires: llvm-devel
BuildRequires: make
BuildRequires: openssl-devel
BuildRequires: pkg-config
BuildRequires: systemd
BuildRequires: tar
BuildRequires: tpm2-tss-devel
Requires(pre): shadow-utils

%description
This package contains the Azure IoT device runtime, comprised of the following services:

- aziot-identityd - The Azure IoT Identity Service
- aziot-certd - The Azure IoT Certificates Service
- aziot-keyd - The Azure IoT Keys Service
- aziot-tpmd - The Azure IoT TPM Service

This package also contains the following libraries:

- libaziot_keys.so - The library used by the Keys Service to communicate with HSMs for key operations.
- <openssl engines directory>/openssl/engines/libaziot_keys.so - An openssl engine that can be used to work with asymmetric keys managed by the Azure IoT Keys Service.

Lastly, this package contains the aziotctl binary that is used to configure and manage the services.

%package devel

Summary: Development files for Azure IoT Identity Service and related services

%description devel
This package contains development files for the Azure IoT device runtime.


%prep

%setup -q

%build

%install
# include rust toolchain that matches the one from iot-identity-service's pipeline
pushd ~
tar xf %{SOURCE3} --no-same-owner --strip-components=1
popd
export CARGO_HOME=~/.cargo
export PATH=$PATH:$CARGO_HOME/bin
export RUSTUP_HOME=~/.rustup

# build and install required rust packages needed for during aziot-identity-service build
# since Mariner Toolkit builds packages offline
pushd ~
tar xf %{SOURCE1} --no-same-owner
tar xf %{SOURCE2} --no-same-owner
popd
cargo install bindgen --path ~/rust-bindgen-@@BINDGEN_VERSION@@ --offline
cargo install cbindgen --path ~/cbindgen-@@CBINDGEN_VERSION@@ --offline

# locate openssl lib directory for Makefile
%define _enginesdir %(openssl version -e | sed 's/ENGINESDIR: //' | sed 's/"//g')

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
    OPENSSL_ENGINE_FILENAME=%{_enginesdir}/aziot_keys.so \
    RELEASE=1 \
    V=1 \
    ARCH=%{_arch} \
    INSTALL_PRESET=false \
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

if ! %{_bindir}/getent group aziottpm >/dev/null; then
    %{_sbindir}/groupadd -r aziottpm
fi
if ! %{_bindir}/getent passwd aziottpm >/dev/null; then
    %{_sbindir}/useradd -r -g aziottpm -c 'aziot-tpmd user' -s /sbin/nologin -d /var/lib/aziot/tpmd aziottpm
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
    %{_sbindir}/usermod -aG aziottpm aziotid
fi


%post
%systemd_post aziot-certd.socket
%systemd_post aziot-identityd.socket
%systemd_post aziot-keyd.socket
%systemd_post aziot-tpmd.socket


%preun
%systemd_preun aziot-certd.socket
%systemd_preun aziot-identityd.socket
%systemd_preun aziot-keyd.socket
%systemd_preun aziot-tpmd.socket


%postun
%systemd_postun_with_restart aziot-certd.service
%systemd_postun_with_restart aziot-identityd.service
%systemd_postun_with_restart aziot-keyd.service
%systemd_postun_with_restart aziot-tpmd.service


%files

# Binaries
%{_libexecdir}/%{name}/aziotd
%{_libexecdir}/%{name}/aziot-certd
%{_libexecdir}/%{name}/aziot-identityd
%{_libexecdir}/%{name}/aziot-keyd
%{_libexecdir}/%{name}/aziot-tpmd

%{_bindir}/aziotctl

# libaziot-keys
%{_libdir}/libaziot_keys.so

# libaziot-key-openssl-engine-shared
%{_enginesdir}/aziot_keys.so

# Default configs and config directories
%attr(400, aziotcs, aziotcs) %{_sysconfdir}/aziot/certd/config.toml.default
%attr(700, aziotcs, aziotcs) %dir %{_sysconfdir}/aziot/certd/config.d

%attr(400, aziotid, aziotid) %{_sysconfdir}/aziot/identityd/config.toml.default
%attr(700, aziotid, aziotid) %dir %{_sysconfdir}/aziot/identityd/config.d

%attr(400, aziotks, aziotks) %{_sysconfdir}/aziot/keyd/config.toml.default
%attr(700, aziotks, aziotks) %dir %{_sysconfdir}/aziot/keyd/config.d

%attr(400, aziottpm, aziottpm) %{_sysconfdir}/aziot/tpmd/config.toml.default
%attr(700, aziottpm, aziottpm) %dir %{_sysconfdir}/aziot/tpmd/config.d

%attr(600, root, root) %{_sysconfdir}/aziot/config.toml.template

# Home directories
%attr(-, aziotcs, aziotcs) %dir /var/lib/aziot/certd
%attr(-, aziotid, aziotid) %dir /var/lib/aziot/identityd
%attr(-, aziotks, aziotks) %dir /var/lib/aziot/keyd
%attr(-, aziottpm, aziottpm) %dir /var/lib/aziot/tpmd

# Systemd services and sockets
%{_unitdir}/aziot-certd.service
%{_unitdir}/aziot-certd.socket
%{_unitdir}/aziot-identityd.service
%{_unitdir}/aziot-identityd.socket
%{_unitdir}/aziot-keyd.service
%{_unitdir}/aziot-keyd.socket
%{_unitdir}/aziot-tpmd.service
%{_unitdir}/aziot-tpmd.socket

%doc README.md
# %doc THIRD-PARTY-NOTICES
%license LICENSE

# exclude build artifacts (notably, those generated by aziot-tpm-sys/azure-iot-hsm-c CMake build)
%exclude %{_builddir}/%{name}-%{version}/target/


%files devel
%{_includedir}/%{name}/aziot-keys.h
%license LICENSE


%changelog
*   Thu Aug 19 2021 Joseph Knierman <joknierm@microsoft.com> @@VERSION@@-4
-   Update work on iotedge pipelines
*   Wed May 05 2021 David Grob <grobdavid@microsoft.com> 1.2.0-3
-   Update to version 1.2.0 and compress source files.
*   Mon Mar 29 2021 David Grob <grobdavid@microsoft.com> 1.2.0-1
-   Original aziot-edge version 1.2.0 post rc4 for Mariner.
