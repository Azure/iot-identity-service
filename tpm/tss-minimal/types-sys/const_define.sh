#! /bin/sh -ex
HEADER=$(find "${1:?}" -name tss2_tpm2_types.h)
test -n "${HEADER}"
(
    IFS=,
    for KEY in ${2:?}
    do
        PREFIX=${KEY%:*}
        ALIAS=${KEY#*:}
        grep "define ${PREFIX}" "${HEADER}" \
        | awk -v ALIAS="${ALIAS}" '{ print ALIAS" const DEF_"$2" = "$2";" }'
    done
) \
| cat wrapper.h.in /dev/fd/0
