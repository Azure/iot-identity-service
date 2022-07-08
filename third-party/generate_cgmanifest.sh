#! /bin/sh -eux

if [ "${1:-}" = "component" ]
then
    # CentOS "git submodule foreach" still uses "eval" to pass variables
    # to the command string.  Variables only began being passed through
    # the environment starting in 1.9.0.
    SHA=$(git rev-parse HEAD)
    URL=$(git ls-remote --get-url origin)
    # $-variables in single-quote string are for jq variable expansion.
    # shellcheck disable=SC2016
    exec jq -n --arg repositoryUrl "${URL}" --arg commitHash "${SHA}" \
        '{ component: { type: "git", git: { $repositoryUrl, $commitHash } } }'
fi

SELF=$(readlink -f "${0}")
git submodule foreach --quiet "${SELF} component" \
| jq -s '{ registrations: . }'
