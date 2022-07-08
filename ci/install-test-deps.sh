#!/bin/bash

# This script is meant to be sourced.
#
# WARNING: This script is destructive to your machine's environment and globally-installed files. For example, the Ubuntu-specific parts of the script
# modify the contents of /etc/apt. The script is intended to be run inside a container of the corresponding OS, not directly on your machine.

. ./ci/install-build-deps.sh

# OS packages

case "$OS" in
    'centos:7')
        export SKIP_TSS_MINIMAL=0

        yum install -y expect json-glib-devel libtasn1-devel net-tools python3 socat
        ;;

    'debian:'*|'ubuntu:'*)
        export SKIP_TSS_MINIMAL=0

        apt-get install -y \
            expect gawk iproute2 libjson-glib-dev libtasn1-6-dev python3 socat
        ;;

    *)
        export SKIP_TSS_MINIMAL=1
        ;;
esac

if [ "$SKIP_TSS_MINIMAL" = 0 ]; then
    (
        cd third-party/libtpms || exit 1;
        ./autogen.sh \
            --disable-dependency-tracking \
            --with-openssl \
            --with-tpm2;
        make -j;
        make install;
    )

    (
        cd third-party/swtpm || exit 1;
        PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./autogen.sh \
            --disable-dependency-tracking \
            --without-seccomp;
        make -j;
        make install;
    )
fi
