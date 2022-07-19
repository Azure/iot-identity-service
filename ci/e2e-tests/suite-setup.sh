#!/bin/bash

# Usage:
#
# ./ci/e2e-tests/suite-setup.sh
#
# See https://github.com/Azure/iot-identity-service/blob/main/docs-dev/e2e-tests.md for details of some env vars that need to be defined.

set -euo pipefail

echo "$0 $*" >&2


GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"

. "$GITHUB_WORKSPACE/ci/e2e-tests/suite-common.sh"


. "$GITHUB_WORKSPACE/ci/e2e-tests/az-login.sh"

source "$GITHUB_WORKSPACE/ci/e2e-tests/helper-functions.sh"


createHub "$suite_common_resource_name"

echo 'Creating DPS...' >&2

dps_resource_id="$(
    az iot dps create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$suite_common_resource_name" \
        --tags "suite_id=$suite_id" \
        --query 'id' --output tsv
)"

createDpsLinkedHub $suite_common_resource_name $suite_common_resource_name $dps_resource_id "suite_id=$suite_id"

echo 'Created DPS' >&2
