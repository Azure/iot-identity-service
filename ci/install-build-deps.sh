#!/bin/bash

# This script is meant to be sourced.


# openssl

case "$CONTAINER_OS" in
    'centos:7')
        case "$OPENSSL_VERSION" in
            '1.0')
                OPENSSL_PACKAGE_NAME='openssl-devel'
                ;;
            *)
                exit 1
                ;;
        esac

        yum install -y \
            curl gcc make pkgconfig \
            clang llvm-devel \
            "$OPENSSL_PACKAGE_NAME"
        ;;

    'debian:9-slim')
        case "$OPENSSL_VERSION" in
            '1.0')
                OPENSSL_PACKAGE_NAME='libssl1.0-dev'
                ;;
            '1.1.0')
                OPENSSL_PACKAGE_NAME='libssl-dev'
                ;;
            *)
                exit 1
                ;;
        esac

        apt-get update
        apt-get install -y \
            curl gcc make pkg-config \
            libclang1 llvm-dev \
            "$OPENSSL_PACKAGE_NAME"
        ;;

    'debian:10-slim')
        case "$OPENSSL_VERSION" in
            '1.1.1')
                OPENSSL_PACKAGE_NAME='libssl-dev'
                ;;
            *)
                exit 1
                ;;
        esac

        apt-get update
        apt-get install -y \
            curl gcc make pkg-config \
            libclang1 llvm-dev \
            "$OPENSSL_PACKAGE_NAME"
        ;;

    *)
        exit 1
esac


# Rust
mkdir -p ~/.cargo/bin

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
