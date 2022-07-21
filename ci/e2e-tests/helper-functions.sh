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

# Sets up a DPS custom allocation policy. The logic in the custom allocation policy
# assigns devices to a 'foo-devices' IoT hub if they have a payload containing
# a 'modelId' field with 'foo' in it. 
function setupCustomAllocationPolicy {
        echo 'Creating an Azure Function for use as a DPS custom allocation policy...' >&2
        
        # Initialize function app project and function
        func init DpsCustomAllocationFunctionProj --dotnet
        pushd DpsCustomAllocationFunctionProj
        func new --name "$dps_allocation_function_name" --template "HTTP trigger" --authlevel "anonymous" --language C# --force
        
        # Copy source code into functino app project
        cp "$GITHUB_WORKSPACE/ci/e2e-tests/DpsCustomAllocation.cs" .

        # Add build deps
        dotnet add package Microsoft.Azure.Devices.Provisioning.Service -v 1.16.3
        dotnet add package Microsoft.Azure.Devices.Shared -v 1.27.0

        # Create storeage account needed by function app
        sa_name="sa${GITHUB_RUN_ID}r${GITHUB_RUN_NUMBER}"
        az storage account create \
            --name $sa_name \
            --location $AZURE_LOCATION \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
            --sku Standard_LRS \
            --tags "suite_id=$suite_id"

        # Create function app
        az functionapp create \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
            --consumption-plan-location $AZURE_LOCATION \
            --runtime dotnet \
            --functions-version 3 \
            --name "$dps_allocation_functionapp_name" \
            --disable-app-insights \
            --storage-account $sa_name \
            --tags "suite_id=$suite_id"

        # Publishing the app sometimes fails, so retry up to 3 times
        set +e
        for retry in {0..3}; do
            if [ "$retry" != "0" ]; then
                sleep 10
            fi
            echo "Publishing the function app. Attempt $retry..."
            func azure functionapp publish "$dps_allocation_functionapp_name" --force
            if [ "$?" == "0" ]; then
                break
            fi
            if [ "$retry" == "3" ]; then
                exit 1
            fi
        done
        set -e
        
        popd
        echo 'Created an Azure Function for use as a DPS custom allocation policy.' >&2

        echo 'Creating a second IoT hub for testing the custom allocation policy...'
        createHub "$foo_devices_iot_hub"
        dps_resource_id=$(az iot dps show \
            --name $suite_common_resource_name \
            --resource-group $AZURE_RESOURCE_GROUP_NAME \
                | jq '.id' -r)
        createDpsLinkedHub $suite_common_resource_name "$foo_devices_iot_hub" $dps_resource_id "suite_id=$suite_id"
        echo 'Created second IoT hub.'
}

# Install tools needed to run the tests
function installTestTools {
    echo 'Installing test tools...' >&2
    distributor_id=$(lsb_release -is)
    os=${distributor_id,,}
    case "$os" in
        debian|ubuntu)
            release=$(lsb_release -rs)
            wget "https://packages.microsoft.com/config/$os/$release/packages-microsoft-prod.deb" \
                -O packages-microsoft-prod.deb
            sudo dpkg -i packages-microsoft-prod.deb
            rm packages-microsoft-prod.deb
            set +e
            for retry in {0..3}; do
                if [ "$retry" != "0" ]; then
                    sleep 10
                fi
                sudo apt-get update -y
                if [ "$?" == "0" ]; then
                    break
                fi
            done
            set -e

            sudo apt-get install -y apt-transport-https dotnet-sdk-6.0 azure-functions-core-tools-4
            ;;
        *)
            echo "Install of test tools unsupported on OS: $os" >&2
            exit 1
            ;;
    esac
    echo 'Installed test tools' >&2    
}
