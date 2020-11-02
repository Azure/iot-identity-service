# End-to-end tests

## Overview

E2E tests are run via the `/ci/e2e-tests.sh` script. Each run of this script creates Azure resources (VM, IoT Hub, etc) to run the tests on.

Put all together, there are three ways to run the script:

- `e2e-tests-scheduled.yaml`: This workflow runs the tests once a day against a list of branches specified as a matrix strategy in the workflow.

- `e2e-tests-manual.yaml`: This workflow can be triggered from the github.com UI to run the tests against a branch of your choice.

- Run the test script locally.


### `e2e-tests-scheduled.yaml` and `e2e-tests-manual.yaml`

The workflows use an Azure service principal and an Azure resource group that the principal must be able to create resources under.

```sh
set -euo pipefail

AZURE_ACCOUNT="$(az account show)"
AZURE_SUBSCRIPTION_ID="$(<<< "$AZURE_ACCOUNT" jq --raw-output '.id')"

export AZURE_RESOURCE_GROUP_NAME='iot-identity-service-e2e-tests'
AZURE_SP_NAME="http://iot-identity-service-e2e-tests"

# The location of the resource group as well as resources created in the group.
AZURE_LOCATION='westcentralus'

az group create --name "$AZURE_RESOURCE_GROUP_NAME" --location "$AZURE_LOCATION"

# Save the output of this command. It contains the password for the SP which cannot be obtained later.
az ad sp create-for-rbac --name "$AZURE_SP_NAME" --skip-assignment

az role assignment create \
    --assignee "$AZURE_SP_NAME" \
    --role 'Contributor' \
    --scope "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$AZURE_RESOURCE_GROUP_NAME"
```

Next, the identity of this SP and the name of this resource group must be set in GitHub secrets on the repo:

- `AZURE_TENANT_ID`: The `tenant` property from the `az ad sp create-for-rbac` output.
- `AZURE_USERNAME`: The `AZURE_SP_NAME` variable in the script.
- `AZURE_PASSWORD`: The `password` property from the `az ad sp create-for-rbac` output.
- `AZURE_RESOURCE_GROUP_NAME`: The `AZURE_RESOURCE_GROUP_NAME` variable in the script.
- `AZURE_LOCATION`: The `AZURE_LOCATION` variable in the script. Note that this can be changed afterwards to start putting the resources in a different location instead of the resource group's location. (The location of a resource group is just a default for new resources.)

At this point, the workflows can be used in the repository.

Note that the `e2e-tests-scheduled.yaml` workflow only runs in the main `Azure/iot-identity-service` repo. It will not run in forks. `e2e-tests-manual.yaml` does not have this restriction and is expected to be how you would run the tests in your fork to validate your work branches, etc.


### Running the script locally

This requires you to have your own Azure subscription. Follow the same steps as the section above to create a resource group and service principal, except for creating GitHub secrets.

If you've never created an IoT Hub under your subscription, you'll need to register the `Microsoft.Devices` Resource Provider. (Make sure to do this while logged in as yourself, not when logged in as the SP, because the SP won't have permissions to do this.)

```sh
az provider register --namespace 'Microsoft.Devices'

# Wait for it to go from "Registering" to "Registered"
watch -c -- az provider show --namespace 'Microsoft.Devices' --query 'registrationState' --output tsv
```

Lastly, in order to download packages for the branch you want to test, you will need a Github Personal Access Token. This token must have the `repo.public_repo` scope. You don't need this if you're instead going to run the tests against packages you've built yourself (with `package.sh`).

Set some more env vars for the parameters of the tests, then run the script.

```sh
# The `tenant` property from the `az ad sp create-for-rbac` output.
export AZURE_TENANT_ID='...'

export AZURE_USERNAME="$AZURE_SP_NAME"

# The `password` property from the `az ad sp create-for-rbac` output.
export AZURE_PASSWORD='...'

# Already done in the setup script.
export AZURE_RESOURCE_GROUP_NAME='iot-identity-service-e2e-tests'

# Already done in the setup script.
#
# As explained in the previous section, you can use a different value here than the resource group's location in order to
# override the location of the resources instead of using the resource group's location.
export AZURE_LOCATION='...'


# When running as a GH action, GH provides the script with a token that it can use for the GH API.
# Since we're running the script ourselves, we have the choice of also using the latest package from a packages workflow run,
# or a locally-built package file.
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

# One of the supported OSes. The GH workflows use a matrix dimension for every supported OS.
export OS='ubuntu:18.04'

# The parameter to the script is the name of the test to run.
~/src/iot-identity-service/ci/e2e-tests.sh 'manual_symmetric_key'
```

Note: The script deletes the resources on exit. If you want to keep the resources around for debugging, comment out the `trap ... EXIT` command.
