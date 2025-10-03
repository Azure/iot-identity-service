#!/bin/bash

# This script is meant to be sourced.
#
# WARNING: This script is destructive to your machine's environment and globally-installed files. For example, the Ubuntu-specific parts of the script
# modify the contents of /etc/apt. The script is intended to be run inside a container of the corresponding OS, not directly on your machine.
if [ -z "${OS:-}" ]; then
    OS="$(. /etc/os-release; echo "${PLATFORM_ID:-$ID:$VERSION_ID}")"
fi

# OS packages

if [ -z "${DISABLE_FOR_CODEQL:-}" ]; then
    case "$OS:$ARCH" in
        'debian:11:amd64'|'debian:12:amd64'|'ubuntu:22.04:amd64'|'ubuntu:24.04:amd64')
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


        'ubuntu:22.04:arm32v7')
            export DEBIAN_FRONTEND=noninteractive
            export TZ=UTC

            sources="$(</etc/apt/sources.list grep . | grep -v '^#' | grep -v '^deb \[arch=amd64\]' || :)"
            if [ -n "$sources" ]; then
                # Update existing repos to be specifically for amd64
                sed -i -e 's/^deb /deb [arch=amd64] /g' /etc/apt/sources.list
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

        'ubuntu:22.04:aarch64')
            export DEBIAN_FRONTEND=noninteractive
            export TZ=UTC

            sources="$(</etc/apt/sources.list grep . | grep -v '^#' | grep -v '^deb \[arch=amd64\]' || :)"
            if [ -n "$sources" ]; then
                # Update existing repos to be specifically for amd64
                sed -i -e 's/^deb /deb [arch=amd64] /g' /etc/apt/sources.list
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

        # Ubuntu 24.04 uses DEB822 format for sources.list, so we have to handle it differently
        'ubuntu:24.04:aarch64'|'ubuntu:24.04:arm32v7')
            export DEBIAN_FRONTEND=noninteractive
            export TZ=UTC

            case "$ARCH" in
                'aarch64')
                    arch_alias='arm64'
                    ;;
                'arm32v7')
                    arch_alias='armhf'
                    ;;
                *)
                    echo "Unexpected ARCH $ARCH" >&2
                    exit 1
                    ;;
            esac

            # Update existing repos to be specifically for amd64
            sed -i -e '/^Architectures:/d' /etc/apt/sources.list.d/ubuntu.sources
            sed -i -e '/^Components:/a Architectures: amd64' /etc/apt/sources.list.d/ubuntu.sources

            # Add arch-specific repos
            </etc/apt/sources.list.d/ubuntu.sources sed \
                -e "s/^Architectures: amd64/Architectures: $arch_alias/g" \
                -e 's|URIs: http://archive.ubuntu.com/ubuntu/|URIs: http://ports.ubuntu.com/ubuntu-ports/|g' \
                -e 's|URIs: http://security.ubuntu.com/ubuntu/|URIs: http://ports.ubuntu.com/ubuntu-ports/|g' \
                >/etc/apt/sources.list.d/ubuntu.ports.sources

            dpkg --add-architecture $arch_alias
            apt-get update
            apt-get upgrade -y
            apt-get install -y --no-install-recommends \
                acl autoconf autoconf-archive automake build-essential ca-certificates \
                clang cmake crossbuild-essential-$arch_alias curl git jq \
                libc-dev:$arch_alias libclang1 libcurl4-openssl-dev:$arch_alias \
                libltdl-dev:$arch_alias libssl-dev:$arch_alias libtool libtss2-dev:$arch_alias \
                llvm-dev pkg-config:$arch_alias
            ;;

        'mariner:2:amd64'|'mariner:2:aarch64'|'azurelinux:3:amd64'|'azurelinux:3:aarch64')
            export DEBIAN_FRONTEND=noninteractive
            export TZ=UTC

            apt-get update
            apt-get upgrade -y
            apt-get install -y \
                acl cmake cpio curl g++ gcc genisoimage git jq libclang1 libssl-dev llvm-dev make \
                pigz pkg-config python3-distutils python3-pip qemu-utils rpm tar wget zstd

            GO_VERSION=1.23.0
            [ "$ARCH" == 'aarch64' ] && GO_ARCH='arm64' || GO_ARCH='amd64'
            mkdir -p /usr/local/go
            curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" | tar -C /usr/local -xzf -
            rm -f /usr/bin/go
            ln -vs /usr/local/go/bin/go /usr/local/bin/go

            touch /.mariner-toolkit-ignore-dockerenv

            case "$OS" in
                'mariner:2')
                    BranchTag='2.0-stable'
                    ;;

                'azurelinux:3')
                    BranchTag='3.0-stable'
                    ;;
            esac

            AzureLinuxToolkitDir='/tmp/azurelinux'
            if ! [ -f "$AzureLinuxToolkitDir/toolkit.tar.gz" ]; then
                rm -rf "$AzureLinuxToolkitDir"
                git clone 'https://github.com/microsoft/azurelinux.git' --branch "$BranchTag" --depth 1 "$AzureLinuxToolkitDir"
                pushd "$AzureLinuxToolkitDir/toolkit/" || exit
                make REBUILD_TOOLS=y package-toolkit
                popd || exit
                cp "$AzureLinuxToolkitDir"/out/toolkit-*.tar.gz "$AzureLinuxToolkitDir/toolkit.tar.gz"
            fi
            ;;

        *)
            echo "Unsupported OS:ARCH $OS:$ARCH" >&2
            exit 1
            ;;
    esac
fi

if [ -z "${DISABLE_FOR_CODEQL:-}" ]; then
    echo "Verifying that third-party/cgmanifest.json is current"
    # SAFETY:
    # The build was started from a fresh image and we are the sole user. The
    # only other way the environment could acquire a rogue ".git" directory
    # is if one of the pipeline steps or dependencies was compromised, in
    # which case the attacker could have run arbitrary commands anyway.
    git config --global safe.directory "*"
    third-party/generate_cgmanifest.sh \
    | diff third-party/cgmanifest.json -
fi

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

# Skip for Azure Linux because it installs the following as part of the specfile.
if [[ "${OS#mariner}" == "$OS" && "${OS#azurelinux}" == "$OS" ]]; then
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
