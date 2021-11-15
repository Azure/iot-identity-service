#!/bin/bash

# Usage:
#
# ./ci/e2e-tests/suite-cleanup.sh
#
# See https://github.com/Azure/iot-identity-service/blob/main/docs-dev/e2e-tests.md for details of some env vars that need to be defined.

set -euo pipefail


echo "$0 $*" >&2


GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"

. "$GITHUB_WORKSPACE/ci/e2e-tests/suite-common.sh"


. "$GITHUB_WORKSPACE/ci/e2e-tests/az-login.sh"


# `az resource list` has `--tag` to filter, but it cannot be combined with `--resource-group`,
# so we need to query with `--resource-group` and then filter using tags ourselves.
#
# Also, sometimes deleting resources fails because `az resource delete` doesn't respect inter-resource dependencies.
# So keep trying it in a loop as long as there are still resources that match.

set +eo pipefail

echo 'Deleting resources...' >&2
while :; do
    ids="$(
        az resource list --resource-group "$AZURE_RESOURCE_GROUP_NAME" |
            jq --arg suite_id "$suite_id" -r '.[] | select(.tags.suite_id == $suite_id).id'
    )"
    printf 'Resources remaining:\n%s\n' "$ids"
    if [ -z "$ids" ]; then
        break
    fi

    # A bug in the latest az CLI causes az resource delete to use an API
    # version not supported by the cloud for DPS instances. For now, we
    # will manually specify the API version when deleting DPS instances.
    #
    # Ref: https://github.com/Azure/azure-cli/issues/20263
    readarray -t ids <<< "$ids"

    dps_ids=""
    other_ids=""
    for resource in "${ids[@]}"
    do
        if [[ "$resource" == *"/Microsoft.Devices/ProvisioningServices/"* ]]; then
            dps_ids+="$resource"$'\n'
        else
            other_ids+="$resource"$'\n'
        fi
    done

    <<< "$dps_ids" timeout 30s xargs az resource delete --api-version 2020-03-01 --ids >/dev/null
    <<< "$other_ids" timeout 30s xargs az resource delete --ids >/dev/null

    sleep 1
    echo 'Retrying...' >&2
done

echo 'Deleted resources' >&2
