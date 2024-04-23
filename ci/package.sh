#!/bin/bash

set -euxo pipefail

cd /src

. ./ci/install-build-deps.sh


mkdir -p packages


case "$OS" in
    'platform:el8'|'platform:el9')
        case "$ARCH" in
            'arm32v7'|'aarch64')
                echo "Cross-compilation on $OS is not supported" >&2
                exit 1
                ;;
        esac

        case "$OS" in
            'platform:el8')
                TARGET_DIR="el8/$ARCH"
                PACKAGE_DIST="el8"
                ;;

            'platform:el9')
                TARGET_DIR="el9/$ARCH"
                PACKAGE_DIST="el9"
                ;;

        esac

        yum -y install rpm-build

        rm -rf ~/rpmbuild

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" PACKAGE_RELEASE="$PACKAGE_RELEASE" PACKAGE_DIST="$PACKAGE_DIST" VENDOR_LIBTSS="${VENDOR_LIBTSS:-0}" V=1 rpm

        rm -rf "packages/$TARGET_DIR"
        mkdir -p "packages/$TARGET_DIR"
        cp \
            ~/"rpmbuild/RPMS/x86_64/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PACKAGE_DIST.x86_64.rpm" \
            ~/"rpmbuild/RPMS/x86_64/aziot-identity-service-debuginfo-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PACKAGE_DIST.x86_64.rpm" \
            ~/"rpmbuild/RPMS/x86_64/aziot-identity-service-devel-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PACKAGE_DIST.x86_64.rpm" \
            ~/"rpmbuild/SRPMS/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PACKAGE_DIST.src.rpm" \
            "packages/$TARGET_DIR/"
        ;;

    'debian:11'|'debian:12'|'ubuntu:20.04'|'ubuntu:22.04')
        DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y dh-make debhelper

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" PACKAGE_RELEASE="$PACKAGE_RELEASE" VENDOR_LIBTSS="${VENDOR_LIBTSS:-0}" V=1 deb

        case "$OS" in
            'debian:11')
                TARGET_DIR="debian11/$ARCH"
                DBGSYM_EXT='deb'
                ;;

            'debian:12')
                TARGET_DIR="debian12/$ARCH"
                DBGSYM_EXT='deb'
                ;;

            'ubuntu:20.04')
                TARGET_DIR="ubuntu2004/$ARCH"
                DBGSYM_EXT='ddeb'
                ;;

            'ubuntu:22.04')
                TARGET_DIR="ubuntu2204/$ARCH"
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

    'mariner:2')
        case "$ARCH" in
            'arm32v7')
                echo "Cross-compilation on $OS is not supported" >&2
                exit 1
                ;;
            'aarch64')
                MarinerArch=aarch64
                ;;
            'amd64')
                MarinerArch=x86_64
                ;;
        esac

        make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" V=1 dist

        MarinerRPMBUILDDIR="/src/Mariner-Build"
        MarinerSpecsDir="$MarinerRPMBUILDDIR/SPECS/aziot-identity-service"
        MarinerSourceDir="$MarinerSpecsDir/SOURCES"

        # Extract built toolkit in building directory
        mkdir -p "$MarinerRPMBUILDDIR"
        cp "$MarinerToolkitDir/toolkit.tar.gz" "$MarinerRPMBUILDDIR/toolkit.tar.gz"
        pushd "$MarinerRPMBUILDDIR"
        tar xzvf toolkit.tar.gz
        popd

        UsePreview=n
        TARGET_DIR="mariner2/$ARCH"
        PackageExtension="cm2"

        # move tarballed iot-identity-service source to building directory
        mkdir -p "$MarinerSourceDir"
        mv "/tmp/aziot-identity-service-$PACKAGE_VERSION.tar.gz" "$MarinerSourceDir/aziot-identity-service-$PACKAGE_VERSION.tar.gz"

        tmp_dir=$(mktemp -d)
        pushd $tmp_dir
        mkdir "rust"
        cp -r ~/.cargo "rust"
        cp -r ~/.rustup "rust"
        tar cf "$MarinerSourceDir/rust.tar.gz" "rust"
        popd

        curl -Lo "/tmp/cbindgen-$CBINDGEN_VERSION.tar.gz" "https://github.com/eqrion/cbindgen/archive/refs/tags/v$CBINDGEN_VERSION.tar.gz"
        pushd /tmp
        tar xf "cbindgen-$CBINDGEN_VERSION.tar.gz" --no-same-owner
        pushd "/tmp/cbindgen-$CBINDGEN_VERSION"
        cp /src/rust-toolchain.toml .
        cargo vendor vendor
        mkdir -p .cargo
        cat > .cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF
        popd
        tar cf "$MarinerSourceDir/cbindgen-$CBINDGEN_VERSION.tar.gz" "cbindgen-$CBINDGEN_VERSION/"
        popd


        curl -Lo "/tmp/rust-bindgen-$BINDGEN_VERSION.tar.gz" "https://github.com/rust-lang/rust-bindgen/archive/refs/tags/v$BINDGEN_VERSION.tar.gz"
        pushd /tmp
        tar xf "rust-bindgen-$BINDGEN_VERSION.tar.gz" --no-same-owner
        pushd "/tmp/rust-bindgen-$BINDGEN_VERSION"
        cp /src/rust-toolchain.toml .
        cargo vendor vendor
        mkdir -p .cargo
        cat > .cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF
        popd
        tar cf "$MarinerSourceDir/rust-bindgen-$BINDGEN_VERSION.tar.gz" "rust-bindgen-$BINDGEN_VERSION/"
        popd

        # Copy spec file to rpmbuild specs directory
        pushd "$MarinerSpecsDir"
        </src/contrib/mariner/aziot-identity-service.signatures.json sed \
            -e "s/@@VERSION@@/$PACKAGE_VERSION/g" \
            -e "s/@@BINDGEN_VERSION@@/$BINDGEN_VERSION/g" \
            -e "s/@@CBINDGEN_VERSION@@/$CBINDGEN_VERSION/g" \
            >aziot-identity-service.signatures.json
        </src/contrib/mariner/aziot-identity-service.spec.in sed \
            -e "s/@@VERSION@@/$PACKAGE_VERSION/g" \
            -e "s/@@RELEASE@@/$PACKAGE_RELEASE/g" \
            -e "s/@@BINDGEN_VERSION@@/$BINDGEN_VERSION/g" \
            -e "s/@@CBINDGEN_VERSION@@/$CBINDGEN_VERSION/g" \
            >aziot-identity-service.spec

        # Build package
        pushd "$MarinerRPMBUILDDIR/toolkit"
        make build-packages LOG_LEVEL=debug PACKAGE_BUILD_LIST="aziot-identity-service" SRPM_FILE_SIGNATURE_HANDLING=update USE_PREVIEW_REPO=$UsePreview CONFIG_FILE= -j "$(nproc)"
        popd

        rm -rf "/src/packages/$TARGET_DIR"
        mkdir -p "/src/packages/$TARGET_DIR"
        cp \
            "$MarinerRPMBUILDDIR/out/RPMS/$MarinerArch/aziot-identity-service-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PackageExtension.$MarinerArch.rpm" \
            "$MarinerRPMBUILDDIR/out/RPMS/$MarinerArch/aziot-identity-service-debuginfo-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PackageExtension.$MarinerArch.rpm" \
            "$MarinerRPMBUILDDIR/out/RPMS/$MarinerArch/aziot-identity-service-devel-$PACKAGE_VERSION-$PACKAGE_RELEASE.$PackageExtension.$MarinerArch.rpm" \
            "/src/packages/$TARGET_DIR"
        ;;

    *)
        echo "Unsupported OS:ARCH $OS:$ARCH" >&2
        exit 1
        ;;
esac
