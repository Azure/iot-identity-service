#! /bin/sh -eux

# `bindgen` cannot expand macros of the form "#define CONSTANT ((TYPE)
# VALUE)".  This script converts such macros to "const" declarations.
# Ref: https://github.com/rust-lang/rust-bindgen/issues/316

HEADER=$(find "${1}" -name tss2_tpm2_types.h)
test -n "${HEADER}"
(
    IFS=,
    for KEY in ${2}
    do
        PREFIX=${KEY%:*}
        ALIAS=${KEY#*:}
        grep "define ${PREFIX}" "${HEADER}" \
        | awk -v ALIAS="${ALIAS}" '{ print ALIAS" const DEF_"$2" = "$2";" }'
    done
) \
| cat wrapper.h.in -
