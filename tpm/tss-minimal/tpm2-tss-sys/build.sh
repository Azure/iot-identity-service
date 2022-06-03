#! /bin/sh -eux

SRC_COPY="${1}"
OUT_PREFIX="${2}"
shift 2

rm -rf "${SRC_COPY}"
rm -rf "${OUT_PREFIX}"

git submodule update --init --depth 1 -- tpm2-tss
git clone tpm2-tss "${SRC_COPY}"
cd "${SRC_COPY}"
./bootstrap
./configure "${@}" --prefix="${OUT_PREFIX}"
export MAKEFLAGS="${CARGO_MAKEFLAGS}"
make
make install
