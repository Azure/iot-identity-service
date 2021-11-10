#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-build-deps.sh


mkdir -p packages


case "$OS" in
    'centos:7'|'platform:el8')
        case "$ARCH" in
            'arm32v7'|'aarch64')
                echo "Cross-compilation on $OS is not supported" >&2
                exit 1
                ;;
        esac

        case "$OS" in
            'centos:7')
                TARGET_DIR="centos7/$ARCH"
                ;;

            'platform:el8')
                TARGET_DIR="el8/$ARCH"
                ;;
        esac

        yum -y install rpm-build

        rm -rf ~/rpmbuild

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" PACKAGE_RELEASE="$PACKAGE_RELEASE" V=1 rpm

        rm -rf "packages/$TARGET_DIR"
        mkdir -p "packages/$TARGET_DIR"
        cp \
            ~/"rpmbuild/RPMS/x86_64/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.x86_64.rpm" \
            ~/"rpmbuild/RPMS/x86_64/aziot-identity-service-devel-$PACKAGE_VERSION-$PACKAGE_RELEASE.x86_64.rpm" \
            ~/"rpmbuild/SRPMS/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.src.rpm" \
            "packages/$TARGET_DIR/"
        ;;

    'debian:9'|'debian:10'|'debian:11'|'ubuntu:18.04'|'ubuntu:20.04')
        DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y dh-make debhelper

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" PACKAGE_RELEASE="$PACKAGE_RELEASE" V=1 deb

        case "$OS" in
            'debian:9')
                TARGET_DIR="debian9/$ARCH"
                DBGSYM_EXT='deb'
                ;;

            'debian:10')
                TARGET_DIR="debian10/$ARCH"
                DBGSYM_EXT='deb'
                ;;

            'debian:11')
                TARGET_DIR="debian11/$ARCH"
                DBGSYM_EXT='deb'
                ;;

            'ubuntu:18.04')
                TARGET_DIR="ubuntu1804/$ARCH"
                DBGSYM_EXT='ddeb'
                ;;

            'ubuntu:20.04')
                TARGET_DIR="ubuntu2004/$ARCH"
                DBGSYM_EXT='ddeb'
                ;;

            *)
                echo 'unreachable' >&2
                exit 1
                ;;
        esac

        case "$ARCH" in
            'amd64')
                BIN_PACKAGE_SUFFIX=amd64
                ;;

            'arm32v7')
                BIN_PACKAGE_SUFFIX=armhf
                ;;

            'aarch64')
                BIN_PACKAGE_SUFFIX=arm64
                ;;
        esac

        rm -rf "packages/$TARGET_DIR"
        mkdir -p "packages/$TARGET_DIR"
        cp \
            "/tmp/aziot-identity-service_$PACKAGE_VERSION-${PACKAGE_RELEASE}_$BIN_PACKAGE_SUFFIX.deb" \
            "/tmp/aziot-identity-service-dbgsym_$PACKAGE_VERSION-${PACKAGE_RELEASE}_$BIN_PACKAGE_SUFFIX.$DBGSYM_EXT" \
            "/tmp/aziot-identity-service_$PACKAGE_VERSION.orig.tar.gz" \
            "/tmp/aziot-identity-service_$PACKAGE_VERSION-$PACKAGE_RELEASE.debian.tar.xz" \
            "/tmp/aziot-identity-service_$PACKAGE_VERSION-$PACKAGE_RELEASE.dsc" \
            "packages/$TARGET_DIR/"
        ;;

    'mariner')
        apt-get update
        apt-get install -y git sudo software-properties-common
        sudo add-apt-repository ppa:longsleep/golang-backports
        apt-get update
        apt -y install make tar wget curl rpm qemu-utils golang-1.13-go genisoimage pigz cpio python-pip python3-distutils
        sudo ln -vs /usr/lib/go-1.13/bin/go /usr/bin/go
        mv /.dockerenv /.dockerenv.old 

        mkdir -p packages

        git clone https://github.com/microsoft/CBL-Mariner.git
        pushd CBL-Mariner
        git checkout "1.0-stable"
        pushd toolkit
        make package-toolkit REBUILD_TOOLS=y
        popd
        mv out/toolkit-*.tar.gz "/src/CBL-Mariner/toolkit.tar.gz"
        popd

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" V=1 dist

        MarinerRPMBUILDDIR=/src/Mariner-Build
        MarinerSpecsDir=$MarinerRPMBUILDDIR/SPECS/aziot-identity-service
        MarinerSourceDir=$MarinerSpecsDir/SOURCES

        # Extract built toolkit in building direectory
        mkdir -p $MarinerRPMBUILDDIR
        pushd $MarinerRPMBUILDDIR
        mv /src/CBL-Mariner/toolkit.tar.gz toolkit.tar.gz
        tar -xzvf toolkit.tar.gz
        popd

        # move tarballed iot-identity-service source to building directory
        mkdir -p $MarinerSourceDir
        mv /tmp/aziot-identity-service-$PACKAGE_VERSION.tar.gz $MarinerSourceDir/aziot-identity-service-$PACKAGE_VERSION.tar.gz

        mkdir /temp
        rustup install stable
        rustup default stable
        wget https://github.com/eqrion/cbindgen/archive/refs/tags/v0.18.0.tar.gz -O /temp/cbindgen-0.15.0.tar.gz
        pushd /temp
        tar xf cbindgen-0.15.0.tar.gz --no-same-owner
        pushd /temp/cbindgen-0.15.0
        cargo vendor vendor
        mkdir /temp/cbindgen-0.15.0/.cargo
        cat > /temp/cbindgen-0.15.0/.cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF
        popd
        tar -cf $MarinerSourceDir/cbindgen-0.15.0.tar.gz cbindgen-0.15.0/
        popd


        wget https://github.com/rust-lang/rust-bindgen/archive/refs/tags/v0.57.0.tar.gz -O /temp/rust-bindgen-0.57.0.tar.gz
        pushd /temp
        tar xf rust-bindgen-0.57.0.tar.gz --no-same-owner
        pushd /temp/rust-bindgen-0.57.0
        cargo vendor vendor
        mkdir /temp/rust-bindgen-0.57.0/.cargo
        cat > /temp/rust-bindgen-0.57.0/.cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF
        popd
        tar -cf $MarinerSourceDir/rust-bindgen-0.57.0.tar.gz rust-bindgen-0.57.0/
        popd

        # Copy spec file to rpmbuild specs directory
        pushd $MarinerSpecsDir
        cp /src/contrib/mariner/aziot-identity-service.spec aziot-identity-service.spec
        cp /src/contrib/mariner/aziot-identity-service.signatures.json aziot-identity-service.signatures.json
        sed -i "s/@@VERSION@@/${PACKAGE_VERSION}/g" aziot-identity-service.signatures.json
        sed -i "s/@@VERSION@@/${PACKAGE_VERSION}/g" aziot-identity-service.spec
        sed -i "s/@@RELEASE@@/${PACKAGE_RELEASE}/g" aziot-identity-service.spec


        # Build package
        pushd $MarinerRPMBUILDDIR/toolkit
        sudo make build-packages PACKAGE_BUILD_LIST="aziot-identity-service" SRPM_FILE_SIGNATURE_HANDLING=update CONFIG_FILE= -j$(nproc)
        popd

        rm -rf "/src/packages/mariner/$ARCH"
        mkdir -p "/src/packages/mariner/$ARCH"
        cp \
            "/src/Mariner-Build/out/RPMS/x86_64/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.cm1.x86_64.rpm" \
            "/src/Mariner-Build/out/RPMS/x86_64/aziot-identity-service-devel-$PACKAGE_VERSION-$PACKAGE_RELEASE.cm1.x86_64.rpm" \
            "/src/packages/mariner/$ARCH/"
        ;;

    *)
        echo "Unsupported OS:ARCH $OS:$ARCH" >&2
        exit 1
        ;;
esac
