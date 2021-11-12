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


# For some reason, `az iot hub create` never returns until the run is timed out,
# even though the IoT Hub finishes creating and becoming "Active" just fine.
# `--debug` reveals that the Async-Operation always returns `{ "state": "Running" }`,
# so something is wrong with ARM.
#
# Work around it by backgrounding the `az iot hub create` command and doing our own monitoring
# of the IoT Hub state. And when we determine the hub is ready, just `kill` the `create` command.
echo 'Creating IoT Hub...' >&2
az iot hub create \
    --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
    --name "$suite_common_resource_name" \
    --sku 'S1' --unit 1 --partition-count 2 \
    --tags "suite_id=$suite_id" \
    --query 'id' --output tsv &
az_iot_hub_create_pid="$!"

echo 'Waiting for IoT Hub to be created and become Active...' >&2
while sleep 1; do
    hub_state="$(
        az iot hub show \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
            --name "$suite_common_resource_name" \
            --query 'properties.state' --output tsv || :
    )"
    echo "IoT Hub is [$hub_state]"
    if [ "$hub_state" = 'Active' ]; then
        kill "$az_iot_hub_create_pid"
        break
    fi
done

echo 'Created IoT Hub' >&2


echo 'Creating DPS...' >&2

dps_resource_id="$(
    az iot dps create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$suite_common_resource_name" \
        --tags "suite_id=$suite_id" \
        --query 'id' --output tsv
)"

az iot dps linked-hub create \
    --resource-group "$AZURE_RESOURCE_GROUP_NAME" --dps-name "$suite_common_resource_name" \
    --connection-string "$(
        az iot hub connection-string show \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" --hub-name "$suite_common_resource_name" \
            --query 'connectionString' --output tsv
    )" \
    --location "$(
        az iot hub show \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" --name "$suite_common_resource_name" \
            --query 'location' --output tsv
    )"

# `az iot dps linked-hub create` deletes the tags on the DPS that
# were set by `az iot dps create` for some unknown reason, so we
# need to tag it again.
#
# A bug in the latest az CLI causes az resource tag to use an API
# version not supported by the cloud. For now, we fill manually
# specify the API version.
#
# Ref: https://github.com/Azure/azure-cli/issues/20263
>/dev/null az resource tag \
    --ids "$dps_resource_id" \
    --tags "suite_id=$suite_id" \
    --api-version 2020-03-01

echo 'Created DPS' >&2
