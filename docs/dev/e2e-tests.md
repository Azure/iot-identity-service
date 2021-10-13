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
AZURE_ACCOUNT="$(az account show)"
AZURE_SUBSCRIPTION_ID="$(<<< "$AZURE_ACCOUNT" jq --raw-output '.id')"

AZURE_RESOURCE_GROUP_NAME='iot-identity-service-e2e-tests'
AZURE_SP_NAME="http://iot-identity-service-e2e-tests"

# The location of the resource group as well as resources created in the group.
AZURE_LOCATION='...'

az group create --name "$AZURE_RESOURCE_GROUP_NAME" --location "$AZURE_LOCATION"

# Save the output of this command. It contains the password for the SP
# which cannot be obtained later.
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
watch -c -- \
    az provider show \
        --namespace 'Microsoft.Devices' \
        --query 'registrationState' --output tsv
```

Lastly, in order to download packages for the branch you want to test, you will need a Github Personal Access Token. This token must have the `repo.public_repo` scope. You don't need this if you're instead going to run the tests against packages you've built yourself (with `package.sh`).

Set some more env vars for the parameters of the tests, then run the script.

```sh
cd ~/src/iot-identity-service

# The `tenant` property from the `az ad sp create-for-rbac` output.
export AZURE_TENANT_ID='...'

export AZURE_USERNAME="$AZURE_SP_NAME"

# The `password` property from the `az ad sp create-for-rbac` output.
export AZURE_PASSWORD='...'

# Already defined in the setup script.
export AZURE_RESOURCE_GROUP_NAME

# Already defined in the setup script.
#
# As explained in the previous section, you can assign a different value here
# than the resource group's location in order to use a different location
# for the resources.
export AZURE_LOCATION


# We can either specify a branch name, in which case the script will fetch
# the latest package built for that branch by the packages workflow.
# For this we need to set some env vars to pass in the PAT as mentioned above
# and to identify the API endpoint and the repository.
export BRANCH='main'
# The format is "$github_username:$pat"
export GITHUB_PAT='foobar:1234abcd'
export GITHUB_API_URL='https://api.github.com'
# Ensure this is set to your fork, if that's what you're running against.
export GITHUB_REPOSITORY='Azure/iot-identity-service'

# Alternatively, we can tell it to use a package file we built ourselves.
# Set the PACKAGE env var to the path of the .deb / .rpm.
#
# export PACKAGE='/path/to/file.deb'


# These are used to ensure the Azure resources don't conflict with
# other resources in the RG. When running in a GH workflow, these env vars
# are set by GH automatically. Here we need to set them ourselves.
export GITHUB_RUN_ID='1000'
export GITHUB_RUN_NUMBER='1'


# One of the supported OSes. The full list can be found in the workflows files.
export OS='ubuntu:18.04'


# Suite-level setup for things shared between all tests (IoT Hub, DPS, etc)
./ci/e2e-tests/suite-setup.sh


# The parameter to the script is the name of the test to run.
# The names can be found in the doc comment at the top of the script.
./ci/e2e-tests/test-run.sh 'manual-symmetric-key'
```

To clean up the test-level resources, run `./ci/e2e-tests/test-cleanup.sh $test_name`

To clean up both suite-level and test-level resources, run `./ci/e2e-tests/suite-cleanup.sh`


# Miscellaenous

1. For AlmaLinux runs (`OS=platform:el8`), you must accept the VM image terms before you can deploy a VM.

   ```sh
   az vm image terms accept --urn '$publisher:$offer:$sku:$version'
   ```

   Get the URN from `/ci/e2e-tests/test-run.sh`

   The Azure SP does not have permissions to do this. Use your regular Azure account.
