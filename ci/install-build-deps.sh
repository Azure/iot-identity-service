#!/bin/bash

# This script is meant to be sourced.
#
# WARNING: This script is destructive to your machine's environment and globally-installed files. For example, the Ubuntu-specific parts of the script
# modify the contents of /etc/apt. The script is intended to be run inside a container of the corresponding OS, not directly on your machine.
if [ -z "${OS:-}" ]; then
    OS="$(. /etc/os-release; echo "${PLATFORM_ID:-$ID:$VERSION_ID}")"
fi

# OS packages

case "$OS:$ARCH" in
    'centos:7:amd64')
        # CentOS pkg-config does not look in /usr/local
        export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"

        yum install -y centos-release-scl epel-release
        yum install -y \
            autoconf autoconf-archive automake clang curl devtoolset-9-gcc devtoolset-9-gcc-c++ \
            git jq libcurl-devel libtool llvm-toolset-7-clang llvm-toolset-7-llvm-devel \
            make openssl openssl-devel pkgconfig

        set +eu # scl_source fails with -eu
        . scl_source enable devtoolset-9 llvm-toolset-7
        set -eu
        ;;

    'centos:7:arm32v7'|'centos:7:aarch64')
        echo "Cross-compilation on $OS $ARCH is not supported" >&2
        exit 1
        ;;

    'debian:10:amd64'|'debian:11:amd64'|'ubuntu:18.04:amd64'|'ubuntu:20.04:amd64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        apt-get update -y
        apt-get upgrade -y
        apt-get install -y \
            acl autoconf autoconf-archive automake build-essential clang cmake \
            curl git jq libclang1 libltdl-dev libssl-dev libtool llvm-dev \
            pkg-config
        ;;

    'debian:10:arm32v7'|'debian:11:arm32v7')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture armhf
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-armhf curl git jq \
            libc-dev:armhf libclang1 libcurl4-openssl-dev:armhf \
            libltdl-dev:armhf libssl-dev:armhf libtool llvm-dev \
            pkg-config
        ;;

    'debian:10:aarch64'|'debian:11:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture arm64
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-arm64 curl git jq \
            libc-dev:arm64 libclang1 libcurl4-openssl-dev:arm64 \
            libltdl-dev:arm64 libssl-dev:arm64 libtool llvm-dev \
            pkg-config
        ;;

    'platform:el8:amd64')
        # RHEL pkg-config does not look in /usr/local
        export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"

        dnf install -y \
            autoconf autoconf-archive automake clang cmake curl gcc gcc-c++ \
            git jq make libcurl-devel libtool llvm-devel openssl openssl-devel \
            pkgconfig
        ;;

    'platform:el8:aarch64'|'platform:el8:arm32v7')
        echo "Cross-compilation on $OS $ARCH is not supported" >&2
        exit 1
        ;;


    'ubuntu:18.04:arm32v7'|'ubuntu:20.04:arm32v7')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        sources="$(</etc/apt/sources.list grep . | grep -v '^#' | grep -v '^deb \[arch=amd64\]' || :)"
        if [ -n "$sources" ]; then
            # Update existing repos to be specifically for amd64
            sed -ie 's/^deb /deb [arch=amd64] /g' /etc/apt/sources.list
        fi

        # Add armhf repos
        </etc/apt/sources.list sed \
            -e 's/^deb \[arch=amd64\] /deb [arch=armhf] /g' \
            -e 's| http://archive.ubuntu.com/ubuntu/ | http://ports.ubuntu.com/ubuntu-ports/ |g' \
            -e 's| http://security.ubuntu.com/ubuntu/ | http://ports.ubuntu.com/ubuntu-ports/ |g' \
            >/etc/apt/sources.list.d/ports.list

        dpkg --add-architecture armhf
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-armhf curl git jq \
            libc-dev:armhf libclang1 libcurl4-openssl-dev:armhf \
            libltdl-dev:armhf libssl-dev:armhf libtool llvm-dev \
            pkg-config
        ;;

    'ubuntu:18.04:aarch64'|'ubuntu:20.04:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        sources="$(</etc/apt/sources.list grep . | grep -v '^#' | grep -v '^deb \[arch=amd64\]' || :)"
        if [ -n "$sources" ]; then
            # Update existing repos to be specifically for amd64
            sed -ie 's/^deb /deb [arch=amd64] /g' /etc/apt/sources.list
        fi

        # Add arm64 repos
        </etc/apt/sources.list sed \
            -e 's/^deb \[arch=amd64\] /deb [arch=arm64] /g' \
            -e 's| http://archive.ubuntu.com/ubuntu/ | http://ports.ubuntu.com/ubuntu-ports/ |g' \
            -e 's| http://security.ubuntu.com/ubuntu/ | http://ports.ubuntu.com/ubuntu-ports/ |g' \
            >/etc/apt/sources.list.d/ports.list

        dpkg --add-architecture arm64
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-arm64 curl git jq \
            libc-dev:arm64 libclang1 libcurl4-openssl-dev:arm64 \
            libltdl-dev:arm64 libssl-dev:arm64 libtool llvm-dev \
            pkg-config
        ;;

    'mariner:1:amd64' | 'mariner:2:amd64' | 'mariner:1:aarch64' | 'mariner:2:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        apt-get update -y
        apt-get upgrade -y
        apt-get install -y software-properties-common
        add-apt-repository -y ppa:longsleep/golang-backports
        apt-get update -y
        apt-get install -y \
            cmake curl gcc g++ git jq make pkg-config \
            libclang1 libssl-dev llvm-dev \
            cpio genisoimage golang-1.17-go qemu-utils pigz python-pip python3-distutils rpm tar wget

        rm -f /usr/bin/go
        ln -vs /usr/lib/go-1.17/bin/go /usr/bin/go
        if [ -f /.dockerenv ]; then
            mv /.dockerenv /.dockerenv.old
        fi

        case "$OS" in
            'mariner:1')
                BranchTag='1.0-stable'
                ;;
            'mariner:2')
                BranchTag='2.0-stable'
                ;;
        esac

        MarinerToolkitDir='/tmp/CBL-Mariner'
        if ! [ -f "$MarinerToolkitDir/toolkit.tar.gz" ]; then
            rm -rf "$MarinerToolkitDir"
            git clone 'https://github.com/microsoft/CBL-Mariner.git' --branch "$BranchTag" --depth 1 "$MarinerToolkitDir"
            pushd "$MarinerToolkitDir/toolkit/" || exit
            make package-toolkit REBUILD_TOOLS=y
            popd || exit
            cp "$MarinerToolkitDir"/out/toolkit-*.tar.gz "$MarinerToolkitDir/toolkit.tar.gz"
        fi
        ;;

    *)
        echo "Unsupported OS:ARCH $OS:$ARCH" >&2
        exit 1
        ;;
esac


# Rust

mkdir -p ~/.cargo/bin
CARGO_BIN=$(readlink -f ~/.cargo/bin)
export PATH="$PATH:$CARGO_BIN"

if ! [ -f ~/.cargo/bin/rustup ]; then
    baseArch="$(uname -m)"
    case "$baseArch" in
        'x86_64')
            curl -Lo ~/.cargo/bin/rustup 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init'
            ;;

        'aarch64')
            curl -Lo ~/.cargo/bin/rustup 'https://static.rust-lang.org/rustup/dist/aarch64-unknown-linux-gnu/rustup-init'
            ;;
        *)
            echo "Unsupported ARCH $baseArch" >&2
            exit 1
            ;;
    esac
    chmod +x ~/.cargo/bin/rustup
    hash -r
fi

# If rustup was already installed, make sure it's up-to-date.
# If it was just installed above, create the hardlinks for cargo, rustc, etc.
rustup self update

# The toolchain specified by rust-toolchain will be automatically installed if it doesn't already exist,
# when `cargo` is run below. We'd like rustup to use the minimal profile to do that so that it doesn't
# use the default profile and download rust-docs, etc.
#
# Ref: https://github.com/rust-lang/rustup/issues/2579
rustup set profile minimal

BINDGEN_VERSION='0.54.0'
CBINDGEN_VERSION='0.15.0'

case "$ARCH" in
    'arm32v7')
        export PKG_CONFIG_ALLOW_CROSS=1

        rustup target add armv7-unknown-linux-gnueabihf
        ;;

    'aarch64')
        export PKG_CONFIG_ALLOW_CROSS=1

        rustup target add aarch64-unknown-linux-gnu
        ;;
esac

# Mariner build installs them as part of the specfile
if [ "$OS" != 'mariner' ]; then
    cargo install bindgen --version "=$BINDGEN_VERSION"

    cargo install cbindgen --version "=$CBINDGEN_VERSION"

    # Ubuntu 18.04 ships a version of patchelf affected by
    # > https://github.com/NixOS/patchelf/issues/10
    # CentOS 7 and RHEL 8 do not have patchelf. patchelf itself is a single C++
    # file, so we just compile it ourselves everywhere instead of futzing
    # around with the build matrix.
    (
        cd third-party/patchelf;
        ./bootstrap.sh;
        ./configure;
        make -j;
        make install-exec;
    )

    if [ "$OS:$ARCH" = 'ubuntu:18.04:amd64' ]; then
        cargo install cargo-tarpaulin --version '^0.18'
    fi
fi

case "$OS:$ARCH" in
    debian:*:arm32v7|ubuntu:*:arm32v7)
        echo '[target.armv7-unknown-linux-gnueabihf]' > ~/.cargo/config
        echo 'linker = "arm-linux-gnueabihf-gcc"' >> ~/.cargo/config
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_LIB_DIR=/usr/lib/arm-linux-gnueabihf
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_INCLUDE_DIR=/usr/include
        ;;

    debian:*:aarch64|ubuntu:*:aarch64)
        echo '[target.aarch64-unknown-linux-gnu]' > ~/.cargo/config
        echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include
        ;;
esac

export CARGO_INCREMENTAL=0

