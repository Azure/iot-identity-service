#! /bin/sh -eux

if [ "${1:-}" = "component" ]
then
    URL=$(git remote get-url origin)
    # $-variables in single-quote string are for jq variable expansion.
    # shellcheck disable=SC2016
    exec jq -n --arg repositoryUrl "${URL}" --arg commitHash "${sha1:?}" \
        '{ component: { type: "git", git: { $repositoryUrl, $commitHash } } }'
fi

SELF=$(readlink -f "${0}")
git submodule foreach --quiet "${SELF} component" \
| jq -s '{ registrations: . }'
