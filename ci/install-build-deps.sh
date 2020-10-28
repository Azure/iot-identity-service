#!/bin/bash

# This script is meant to be sourced.
#
# WARNING: This script is destructive to your machine's environment and globally-installed files. For example, the Ubuntu-specific parts of the script
# modify the contents of /etc/apt. The script is intended to be run inside a container of the corresponding OS, not directly on your machine.


OS="$(. /etc/os-release; echo "$ID:$VERSION_ID")"


# OS packages

case "$OS:$ARCH" in
    'centos:7:amd64')
        yum install -y epel-release
        yum install -y \
            curl gcc jq make pkgconfig \
            clang llvm-devel openssl-devel
        ;;

    'centos:7:arm32v7'|'centos:7:aarch64')
        echo 'Cross-compilation on CentOS 7 is not supported' >&2
        exit 1
        ;;

    'debian:9:amd64'|'debian:10:amd64'|'ubuntu:18.04:amd64'|'ubuntu:20.04:amd64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        apt-get update -y
        apt-get upgrade -y
        apt-get install -y \
            curl gcc jq make pkg-config \
            libclang1 libssl-dev llvm-dev
        ;;

    'debian:9:arm32v7'|'debian:10:arm32v7')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture armhf
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            ca-certificates curl gcc gcc-arm-linux-gnueabihf jq make pkg-config \
            libc-dev libc-dev:armhf libclang1 libssl-dev:armhf llvm-dev
        ;;

    'debian:9:aarch64'|'debian:10:aarch64')
        export DEBIAN_FRONTEND=noninteractive
        export TZ=UTC

        dpkg --add-architecture arm64
        apt-get update -y
        apt-get upgrade -y
        apt-get install -y --no-install-recommends \
            ca-certificates curl gcc gcc-aarch64-linux-gnu jq make pkg-config \
            libc-dev libc-dev:arm64 libclang1 libssl-dev:arm64 llvm-dev
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
            build-essential ca-certificates curl gcc gcc-arm-linux-gnueabihf jq make pkg-config \
            libc-dev libc-dev:armhf libclang1 libssl-dev:armhf llvm-dev
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
            build-essential ca-certificates curl gcc gcc-aarch64-linux-gnu jq make pkg-config \
            libc-dev libc-dev:arm64 libclang1 libssl-dev:arm64 llvm-dev
        ;;

    *)
        echo "Unsupported OS:ARCH $OS:$ARCH" >&2
        exit 1
esac


# Rust

mkdir -p ~/.cargo/bin

# shellcheck disable=SC2155
export PATH="$PATH:$(realpath ~/.cargo/bin)"

if [ -f ~/.cargo/bin/rustup ]; then
    rustup self update
else
    curl -Lo ~/.cargo/bin/rustup 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init'
    chmod +x ~/.cargo/bin/rustup
    hash -r
fi

RUST_TOOLCHAIN="$(cat /src/rust-toolchain)"
rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component clippy,rustfmt
rustup default "$RUST_TOOLCHAIN"

if [ ! -f ~/.cargo/bin/bindgen ]; then
    cargo install bindgen --version '^0.54'
fi

if [ ! -f ~/.cargo/bin/cbindgen ]; then
    cargo install cbindgen --version '^0.14'
fi

export CARGO_INCREMENTAL=0

case "$ARCH" in
    'arm32v7')
        rustup target add armv7-unknown-linux-gnueabihf
        ;;

    'aarch64')
        rustup target add aarch64-unknown-linux-gnu
        ;;
esac

case "$OS:$ARCH" in
    debian:*:arm32v7|ubuntu:*:arm32v7)
        mkdir -p ~/.cargo
        echo '[target.armv7-unknown-linux-gnueabihf]' > ~/.cargo/config
        echo 'linker = "arm-linux-gnueabihf-gcc"' >> ~/.cargo/config
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_LIB_DIR=/usr/lib/arm-linux-gnueabihf
        export ARMV7_UNKNOWN_LINUX_GNUEABIHF_OPENSSL_INCLUDE_DIR=/usr/include
        ;;

    debian:*:aarch64|ubuntu:*:aarch64)
        mkdir -p ~/.cargo
        echo '[target.aarch64-unknown-linux-gnu]' > ~/.cargo/config
        echo 'linker = "aarch64-linux-gnu-gcc"' >> ~/.cargo/config
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include
        ;;
esac
