# End-to-end tests

## Overview

E2E tests are run in a GitHub Actions workflow. Currently the workflow is triggered manually, and takes the branch it should run on as an input.

The workflow then creates Azure resources to run the tests on.


## Setup

To run the tests on your own subscription, you need:

- A Github Personal Access Token. This token must have the `repo.public_repo` scope. This is only needed if you want to run the script against the latest build of a packages workflow, as opposed to using a locally-built package file.

- An Azure subscription.

- An Azure resource group. The E2E tests create resources under this RG. The rest of this document assumes the RG is named "iot-identity-service-e2e-tests"

- An Azure service principal. The E2E tests use this SP to create resources. The rest of this document assumes the SP is named "http://iot-identity-service-e2e-tests"

```sh
set -euo pipefail

AZURE_ACCOUNT="$(az account show)"
AZURE_SUBSCRIPTION_ID="$(<<< "$AZURE_ACCOUNT" jq --raw-output '.id')"

export AZURE_RESOURCE_GROUP_NAME='iot-identity-service-e2e-tests'
AZURE_SP_NAME="http://iot-identity-service-e2e-tests"

az group create --name "$AZURE_RESOURCE_GROUP_NAME" --location 'West US 2'

# Save the output of this command. It contains the password for the SP which cannot be obtained later.
az ad sp create-for-rbac --name "$AZURE_SP_NAME" --skip-assignment

az role assignment create \
    --assignee "$AZURE_SP_NAME" \
    --role 'Contributor' \
    --scope "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$AZURE_RESOURCE_GROUP_NAME"
```

If you've never created an IoT Hub under your subscription, you'll need to register the `Microsoft.Devices` Resource Provider. (Make sure to do this while logged in as yourself, not when logged in as the SP, because the SP won't have permissions to do this.)

```sh
az provider register --namespace 'Microsoft.Devices'

# Wait for it to go from "Registering" to "Registered"
watch -c -- az provider show --namespace 'Microsoft.Devices' --query 'registrationState' --output tsv
```

## Run

Set some more env vars for the parameters of the tests, then run the script.

```sh
mkdir -p /tmp/aziot-e2e
cd /tmp/aziot-e2e

# When running as a GH action, these env vars come from secrets.
# Since we're running the script ourselves, we need to set these according to the SP we created in the previous section.
export AZURE_TENANT_ID='...'
export AZURE_USERNAME='...'
export AZURE_PASSWORD='...'
export AZURE_RESOURCE_GROUP_NAME='iot-identity-service-e2e-tests'


# When running as a GH action, GH provides the script with a token that it can use for the GH API.
# Since we're running the script ourselves, we have the choice of also using the latest package from a packages workflow run,
# or a locally-build package file.
#
# For the former case, we need to give it a PAT instead, along with env vars used for the API requests and to identify the branch
# to download the package for.
#
# The value is of the format "$github_username:$pat"
export GITHUB_PAT='foobar:1234abcd'
export GITHUB_API_URL='https://api.github.com'
export GITHUB_REPOSITORY='Azure/iot-identity-service'
export BRANCH='main'

# For the latter case, set the PACKAGE env var to the path of the .deb or .rpm instead.
#
# export PACKAGE='/path/to/file.deb'

# These are used to ensure the Azure resources don't conflict with other resources in the RG.
# When running as a GH action, these env vars will be automatically set by GH.
export GITHUB_RUN_ID='1000'
export GITHUB_RUN_NUMBER='1'

# One of the supported OSes. The GH action uses a matrix for every supported OS.
export OS='ubuntu:18.04'

~/src/iot-identity-service/ci/e2e-tests.sh 'manual_symmetric_key'
```

Note: The script deletes the resources on exit. If you want to keep the resources around for debugging, comment out the `trap ... EXIT` command.
