#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-build-deps.sh

apt-get install -y --no-install-recommends \
    golang

mkdir -p packages

git clone https://github.com/microsoft/CBL-Mariner.git
pushd CBL-Mariner
git checkout "1.0-stable"
pushd toolkit
make package-toolkit REBUILD_TOOLS=y
popd
mv out/toolkit-*.tar.gz "/src/CBL-Mariner/toolkit.tar.gz"
popd

make ARCH="$ARCH" PACKAGE_VERSION="$PACKAGE_VERSION" PACKAGE_RELEASE="$PACKAGE_RELEASE" V=1 mrpm

rm -rf "packages/mariner/$ARCH"
mkdir -p "packages/mariner/$ARCH"
cp \
    ~/"CBL-Mariner/out/RPMS/x86_64/aziot-identity-service-$PACKAGE_VERSION-4.x86_64.rpm" \
    ~/"CBL-Mariner/out/RPMS/x86_64/aziot-identity-service-devel-$PACKAGE_VERSION-4.x86_64.rpm" \
    ~/"CBL-Mariner/out/SRPMS/aziot-identity-service-$PACKAGE_VERSION-4.src.rpm" \
    "packages/mariner/$ARCH/"
