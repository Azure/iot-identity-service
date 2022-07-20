#!/bin/bash

# This file contains several helper functions. These functions expect that
# certain env vars are already set including $suite_id and $AZURE_RESOURCE_GROUP_NAME.

# Create an IoT Hub instance.
# Parameters:
#   $1 - IoT hub name
function createHub {
    # For some reason, `az iot hub create` never returns until the run is timed out,
    # even though the IoT Hub finishes creating and becoming "Active" just fine.
    # `--debug` reveals that the Async-Operation always returns `{ "state": "Running" }`,
    # so something is wrong with ARM.
    #
    # Work around it by backgrounding the `az iot hub create` command and doing our own monitoring
    # of the IoT Hub state. And when we determine the hub is ready, just `kill` the `create` command.
    echo "Creating IoT Hub: $1..." >&2
    az iot hub create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$1" \
        --sku 'S1' --unit 1 --partition-count 2 \
        --tags "suite_id=$suite_id" \
        --query 'id' --output tsv &
    az_iot_hub_create_pid="$!"

    echo 'Waiting for IoT Hub to be created and become Active...' >&2
    while sleep 1; do
        hub_state="$(
            az iot hub show \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                --name $1 \
                --query 'properties.state' --output tsv || :
        )"
        echo "IoT Hub is [$hub_state]"
        if [ "$hub_state" = 'Active' ]; then
            kill "$az_iot_hub_create_pid"
            break
        fi
    done

    echo 'Created IoT Hub' >&2
}

# Link an IoT hub with a DPS instance.
# Parameters:
#   $1 - DPS name
#   $2 - IoT hub name
#   $3 - DPS resource id
#   $4 - tags for DPS instance
function createDpsLinkedHub {
    az iot dps linked-hub create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" --dps-name "$1" \
        --connection-string "$(
            az iot hub connection-string show \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" --hub-name "$2" \
                --query 'connectionString' --output tsv
        )" \
        --location "$(
            az iot hub show \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" --name "$2" \
                --query 'location' --output tsv
        )"

    # `az iot dps linked-hub create` deletes the tags on the DPS that
    # were set by `az iot dps create` for some unknown reason, so we
    # need to tag it again.
    #
    # A bug in the latest az CLI causes az resource tag to use an API
    # version not supported by the cloud. For now, we will manually
    # specify the API version.
    #
    # Ref: https://github.com/Azure/azure-cli/issues/20263
    >/dev/null az resource tag \
        --ids "$3" \
        --tags "$4" \
        --api-version 2020-03-01
}

# Creates a DPS custom allocation policy. This includes creating a device payload
# file using the specified file name, and creating an additional IoT hub instance.
# The logic in the custom allocation policy is implemented such that it assigns devices
# to the new IoT hub when their payload matches the content in the generated payload file.
#
# Parameters:
#   $1 payload_filename - The name to use for the generated device payload file
#   $2 iot_hub_name - Name of the IoT hub to which the allocation policy should assign the device
#   $3 webhook_url - The URL of the generated function app will be returned via this variable
function createCustomAllocationPolicy {
        local payload_filename=$1
        local iot_hub_name=$2
        local __webhook_url=$3
        echo 'Creating an Azure Function for use as a DPS custom allocation policy...' >&2
        func init DpsCustomAllocationFunctionProj --dotnet
        pushd DpsCustomAllocationFunctionProj
        func new --name DpsCustomAllocation --template "HTTP trigger" --authlevel "anonymous" --language C# --force
        dotnet add package Microsoft.Azure.Devices.Provisioning.Service -v 1.16.3
        dotnet add package Microsoft.Azure.Devices.Shared -v 1.27.0
        cp "$GITHUB_WORKSPACE/ci/e2e-tests/DpsCustomAllocation.cs" .
        az storage account create \
            --name customallocationstorage \
            --location $AZURE_LOCATION \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
            --sku Standard_LRS
        az functionapp create \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
            --consumption-plan-location $AZURE_LOCATION \
            --runtime dotnet \
            --functions-version 3 \
            --name DpsCustomAllocationApp \
            --storage-account customallocationstorage
        eval $__webhook_url=$(func azure functionapp publish DpsCustomAllocationApp --force | awk -F ': ' '/Invoke url/ { print $2 }')
        popd
        echo 'Created an Azure Function for use as a DPS custom allocation policy.' >&2

        echo 'Creating a second IoT hub for testing the custom allocation policy...'
        createHub $2
        dps_resource_id=$(az iot dps show \
            --name $suite_common_resource_name \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
                | jq '.id' -r)
        createDpsLinkedHub $suite_common_resource_name $2 $dps_resource_id "suite_id=$suite_id"
        echo 'Created second IoT hub.'

        echo 'Generating payload file...' >&2
        >"$1" cat <<-EOF
{
    "modelId": "foo 2022"
}
EOF
        echo 'Generated payload file.' >&2

}