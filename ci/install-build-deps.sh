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
    'debian:11:amd64'|'debian:12:amd64'|'ubuntu:20.04:amd64'|'ubuntu:22.04:amd64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        apt-get update
        apt-get upgrade -y
        apt-get install -y \
            acl autoconf autoconf-archive automake build-essential clang cmake \
            curl git jq libclang1 libltdl-dev libssl-dev libtss2-dev libtool \
            llvm-dev pkg-config
        ;;

    'debian:11:arm32v7')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture armhf
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-armhf curl git jq \
            libc-dev:armhf libclang1 libcurl4-openssl-dev:armhf \
            libltdl-dev:armhf libssl-dev:armhf libtool libtss2-dev:armhf \
            llvm-dev pkg-config
        ;;

    'debian:12:arm32v7')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture armhf
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-armhf curl git jq \
            libc-dev:armhf libclang1 libcurl4-openssl-dev:armhf \
            libltdl-dev:armhf libssl-dev:armhf libtool libtss2-dev:armhf \
            llvm-dev pkg-config:armhf
        ;;

    'debian:11:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture arm64
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-arm64 curl git jq \
            libc-dev:arm64 libclang1 libcurl4-openssl-dev:arm64 \
            libltdl-dev:arm64 libssl-dev:arm64 libtool libtss2-dev:arm64 \
            llvm-dev pkg-config
        ;;
    
    'debian:12:aarch64')
    'debian:11:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture arm64
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-arm64 curl git jq \
            libc-dev:arm64 libclang1 libcurl4-openssl-dev:arm64 \
            libltdl-dev:arm64 libssl-dev:arm64 libtool libtss2-dev:arm64 \
            llvm-dev pkg-config:arm64
        ;;

    'platform:el8:amd64')
        export VENDOR_LIBTSS=1

        dnf install -y \
            autoconf autoconf-archive automake clang cmake curl gcc gcc-c++ \
            git jq make libcurl-devel libtool llvm-devel openssl openssl-devel \
            pkgconfig
        ;;

    'platform:el9:amd64')
        export VENDOR_LIBTSS=1

        dnf install -y \
            autoconf autoconf-archive automake clang cmake diffutils gcc gcc-c++ \
            git jq make libcurl-devel libtool llvm-devel openssl-devel \
            pkgconfig
        ;;

    'platform:el8:aarch64'|'platform:el8:arm32v7'|'platform:el9:aarch64'|'platform:el9:arm32v7')
        echo "Cross-compilation on $OS $ARCH is not supported" >&2
        exit 1
        ;;


    'ubuntu:20.04:arm32v7'|'ubuntu:22.04:arm32v7')
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
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-armhf curl git jq \
            libc-dev:armhf libclang1 libcurl4-openssl-dev:armhf \
            libltdl-dev:armhf libssl-dev:armhf libtool libtss2-dev:armhf \
            llvm-dev pkg-config
        ;;

    'ubuntu:20.04:aarch64'|'ubuntu:22.04:aarch64')
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
        apt-get update
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            acl autoconf autoconf-archive automake build-essential ca-certificates \
            clang cmake crossbuild-essential-arm64 curl git jq \
            libc-dev:arm64 libclang1 libcurl4-openssl-dev:arm64 \
            libltdl-dev:arm64 libssl-dev:arm64 libtool libtss2-dev:arm64 \
            llvm-dev pkg-config
        ;;

    'mariner:2:amd64' | 'mariner:2:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        apt-get update
        apt-get upgrade -y
        apt-get install -y software-properties-common
        add-apt-repository -y ppa:longsleep/golang-backports
        apt-get update
        apt-get install -y \
            cmake curl gcc g++ git jq make pkg-config \
            libclang1 libssl-dev llvm-dev \
            cpio genisoimage golang-1.20-go qemu-utils pigz python3-pip python3-distutils rpm tar wget

        rm -f /usr/bin/go
        ln -vs /usr/lib/go-1.20/bin/go /usr/bin/go
        if [ -f /.dockerenv ]; then
            mv /.dockerenv /.dockerenv.old
        fi

        BranchTag='2.0-stable'
        MarinerToolkitDir='/tmp/CBL-Mariner'
        if ! [ -f "$MarinerToolkitDir/toolkit.tar.gz" ]; then
            rm -rf "$MarinerToolkitDir"
            git clone 'https://github.com/microsoft/CBL-Mariner.git' --branch "$BranchTag" --depth 1 "$MarinerToolkitDir"
            pushd "$MarinerToolkitDir/toolkit/" || exit
            make REBUILD_TOOLS=y package-toolkit
            popd || exit
            cp "$MarinerToolkitDir"/out/toolkit-*.tar.gz "$MarinerToolkitDir/toolkit.tar.gz"
        fi
        ;;

    *)
        echo "Unsupported OS:ARCH $OS:$ARCH" >&2
        exit 1
        ;;
esac

echo "Verifying that third-party/cgmanifest.json is current"
# SAFETY:
# The build was started from a fresh image and we are the sole user. The
# only other way the environment could acquire a rogue ".git" directory
# is if one of the pipeline steps or dependencies was compromised, in
# which case the attacker could have run arbitrary commands anyway.
git config --global safe.directory "*"
third-party/generate_cgmanifest.sh \
| diff third-party/cgmanifest.json -

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

BINDGEN_VERSION='0.69.4'
CBINDGEN_VERSION='0.26.0'

case "$ARCH" in
    'amd64')
        ;;

    'arm32v7')
        export PKG_CONFIG_armv7_unknown_linux_gnueabihf="arm-linux-gnueabihf-pkg-config"

        rustup target add armv7-unknown-linux-gnueabihf
        ;;

    'aarch64')
        export PKG_CONFIG_aarch64_unknown_linux_gnu="aarch64-linux-gnu-pkg-config"

        rustup target add aarch64-unknown-linux-gnu
        ;;
esac

# Mariner build installs the following as part of the specfile.
if [ "${OS#mariner}" = "$OS" ]; then
    cargo install bindgen-cli --version "=$BINDGEN_VERSION" --locked

    cargo install cbindgen --version "=$CBINDGEN_VERSION" --locked

    if [ "$OS:$ARCH" = 'ubuntu:22.04:amd64' ]; then
        cargo install cargo-tarpaulin --version '^0.20' --locked
    fi
fi

case "$OS:$ARCH" in
    debian:*:arm32v7|ubuntu:*:arm32v7)
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_LIB_DIR=/usr/lib/arm-linux-gnueabihf
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_INCLUDE_DIR=/usr/include

        echo '[target.armv7-unknown-linux-gnueabihf]' > ~/.cargo/config
        echo 'linker = "arm-linux-gnueabihf-gcc"' >> ~/.cargo/config
        ;;

    debian:*:aarch64|ubuntu:*:aarch64)
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include

        echo '[target.aarch64-unknown-linux-gnu]' > ~/.cargo/config
        echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config
        ;;
esac

export CARGO_INCREMENTAL=0
