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

    # NOTE: ubuntu:20.04 uses libtss2-dev provided through the package
    # repositories, but the available version does not provide a TCTI
    # module for swtpm.  So, we skip testing tss-minimal on
    # ubuntu:20.04.
    'debian:'*|'ubuntu:18.04')
        export SKIP_TSS_MINIMAL=0

        apt-get install -y \
            expect gawk libjson-glib-dev libtasn1-6-dev net-tools python3 socat
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
