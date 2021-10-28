#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-build-deps.sh

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

# move tarballed IIS source to building directory
mkdir -p $MarinerSourceDir
mv /tmp/aziot-identity-service-$PACKAGE_VERSION.tar.gz $MarinerSourceDir/aziot-identity-service-$PACKAGE_VERSION.tar.gz

mkdir /temp
rustup install stable
rustup default stable
wget https://github.com/eqrion/cbindgen/archive/refs/tags/v0.18.0.tar.gz -O /temp/cbindgen-0.18.0.tar.gz
pushd /temp
tar xf cbindgen-0.18.0.tar.gz --no-same-owner
pushd /temp/cbindgen-0.18.0
cargo vendor vendor
mkdir /temp/cbindgen-0.18.0/.cargo
cat > /temp/cbindgen-0.18.0/.cargo/config << EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF
popd
tar -cf $MarinerSourceDir/cbindgen-0.18.0.tar.gz cbindgen-0.18.0/
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


# Build package
pushd $MarinerRPMBUILDDIR/toolkit
sudo make build-packages PACKAGE_BUILD_LIST="aziot-identity-service" SRPM_FILE_SIGNATURE_HANDLING=update CONFIG_FILE= -j$(nproc)
popd

rm -rf "/src/packages/mariner/$ARCH"
mkdir -p "/src/packages/mariner/$ARCH"
cp \
    "/src/Mariner-Build/out/RPMS/x86_64/aziot-identity-service-$PACKAGE_VERSION-2.cm1.x86_64.rpm" \
    "/src/Mariner-Build/out/RPMS/x86_64/aziot-identity-service-devel-$PACKAGE_VERSION-2.cm1.x86_64.rpm" \
    "/src/packages/mariner/$ARCH/"