#!/bin/bash

# Usage:
#
# e2e-tests.sh <test_name>
#
# See https://azure.github.io/iot-identity-service/dev/e2e-tests.html for details of some env vars that need to be defined.
#
# <test_name>:
#     manual-symmetric-key

set -euo pipefail


get_package() {
    if [ -n "${PACKAGE:-}" ]; then
        echo "Using package specified by PACKAGE" >&2
        printf '%s\n' "$PACKAGE"
        return
    fi

    # The download-artifact does not have a way to download artifacts from other workflows.
    # Ref: https://github.com/actions/download-artifact/issues/3
    #
    # So instead we use the GitHub API ourselves.
    #
    # It would be nice to use the v4 graphql API and get the artifact URL in one shot,
    # but it doesn't appear to support artifacts.

    github_curl() {
        if [ -n "${GITHUB_PAT:-}" ]; then
            curl --user "$GITHUB_PAT" "$@"
        elif [ -n "${GITHUB_TOKEN:-}" ]; then
            curl --header "authorization: Bearer $GITHUB_TOKEN" "$@"
        else
            echo 'Neither PACKAGE nor GITHUB_PAT nor GITHUB_TOKEN have been set.' >&2
            exit 1
        fi
    }

    # Get workflow runs for this branch and pick the latest one (the first one).
    # From that, get the artifacts URL.
    #
    # Ref: https://docs.github.com/en/free-pro-team@latest/rest/reference/actions#list-workflow-runs
    echo "Getting latest workflow run's artifacts URL..." >&2
    artifacts_url="$(
        github_curl -L \
            -H 'accept: application/vnd.github.v3+json' \
            "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/workflows/packages.yaml/runs?branch=$BRANCH&event=push&status=success" |
            jq -r '.workflow_runs[0].artifacts_url'
    )"
    if [ "$artifacts_url" = 'null' ]; then
        echo "No successfully-concluded packages workflow found for branch $BRANCH" >&2
        exit 1
    fi
    echo "Artifacts URL: $artifacts_url" >&2

    case "$OS" in
        'centos:7')
            artifact_name='centos-7'
            ;;

        'debian:9')
            artifact_name='debian-9-slim'
            ;;

        'debian:10')
            artifact_name='debian-10-slim'
            ;;

        'ubuntu:18.04')
            artifact_name='ubuntu-18.04'
            ;;

        'ubuntu:20.04')
            artifact_name='ubuntu-20.04'
            ;;

        *)
            echo "Unsupported OS $OS" >&2
            exit 1
            ;;
    esac
    artifact_name="packages_${artifact_name}_amd64"

    echo 'Getting artifact download URL...' >&2
    artifact_download_url="$(
        github_curl -L \
            -H 'accept: application/vnd.github.v3+json' \
            "$artifacts_url" |
            jq \
                --arg artifact_name "$artifact_name" \
                -r \
                '.artifacts[] | select(.name == $artifact_name) | .archive_download_url'
    )"
    if [ -z "$artifact_download_url" ]; then
        echo "Could not find artifact for OS $OS" >&2
        exit 1
    fi
    echo "Artifact download URL: $artifact_download_url" >&2

    echo 'Downloading artifact...' >&2
    github_curl -L \
        -o package.zip \
        "$artifact_download_url"
    echo 'Downloaded artifact' >&2


    echo 'Extracting package...' >&2
    case "$OS" in
        'centos:7')
            unzip -j package.zip 'centos7/amd64/aziot-identity-service-*.x86_64.rpm' -x '*-debuginfo-*.rpm' '*-devel-*.rpm' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service-*.x86_64.rpm
            ;;

        'debian:9')
            unzip -j package.zip 'debian9/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        'debian:10')
            unzip -j package.zip 'debian10/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        'ubuntu:18.04')
            unzip -j package.zip 'ubuntu1804/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        'ubuntu:20.04')
            unzip -j package.zip 'ubuntu2004/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        *)
            echo "Unsupported OS $OS" >&2
            exit 1
            ;;
    esac
    echo 'Extracted package' >&2
}


# Test required variables early to avoid downloading the artifact unnecessarily.
if [ -z "${AZURE_TENANT_ID:-}" ]; then
    echo 'AZURE_TENANT_ID not set' >&2
    exit 1
fi
if [ -z "${AZURE_USERNAME:-}" ]; then
    echo 'AZURE_USERNAME not set' >&2
    exit 1
fi
if [ -z "${AZURE_PASSWORD:-}" ]; then
    echo 'AZURE_PASSWORD not set' >&2
    exit 1
fi

test_name="$1"


run_id="$OS:$GITHUB_RUN_ID:$GITHUB_RUN_NUMBER:$test_name"
echo "Run ID: $run_id" >&2

GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"


# Temp directory used as scratch space to store the downloaded package from GitHub
# and the config files for the package that are scp'd to the test VM.
working_directory="/tmp/iot-identity-service-e2e-tests-${run_id//:/-}"
echo "Working directory: $working_directory" >&2
mkdir -p "$working_directory"
cd "$working_directory"


package="$(get_package)"
echo "Using package at [$package]" >&2
if ! [ -f "$package" ]; then
    echo 'Could not find package file' >&2
    exit 1
fi


echo 'Installing and updating azure-iot extension...' >&2
az extension add --name azure-iot
az extension update --name azure-iot
echo 'Installed and updated azure-iot extension' >&2


echo 'Logging in to Azure...' >&2
>/dev/null az login --service-principal \
    --tenant "$AZURE_TENANT_ID" \
    --username "$AZURE_USERNAME" \
    "--password=$AZURE_PASSWORD"
echo 'Logged in to Azure' >&2

if [ -n "${AZURE_LOCATION:-}" ]; then
    az configure --defaults "location=$AZURE_LOCATION"
fi

# VM image as taken by `az vm create` is specified as `$publisher:$offer:$sku:$version`
#
# Commented-out commands show how to query the SKU and version if needed to update.
# When possible, use the SKU that has a `-gen2` suffix so that it creates a Gen 2 VM instead of a Gen 1 VM.
# (The VM generation is determined by the SKU.)
#
# `--publisher` and `--offer` are useful to filter server-side. But they filter as substrings and return many irrelevant matches,
# so the commands also filter for exact matches using `--query`. `--sku` is left as a substring match so that the query doesn't have to
# give a specific minor version.
#
# Choice of publisher is determined by
# https://docs.microsoft.com/en-us/troubleshoot/azure/cloud-services/support-linux-open-source-technology
case "$OS" in
    'centos:7')
        # az vm image list --all \
        #     --publisher 'OpenLogic' --offer 'CentOS' --sku '7' \
        #     --query "[?publisher == 'OpenLogic' && offer == 'CentOS'].{ sku: sku, version: version }" --output table
        vm_image='OpenLogic:CentOS:7_8-gen2:7.8.2020100701'
        ;;

    'debian:9')
        # az vm image list --all \
        #     --publisher 'credativ' --offer 'Debian' --sku '9' \
        #     --query "[?publisher == 'credativ' && offer == 'Debian'].{ sku: sku, version: version }" --output table
        vm_image='credativ:Debian:9:9.20200722.0'
        ;;

    'debian:10')
        # Not listed on the docs.microsoft.com page, but credativ doesn't publish Debian 10 images.
        #
        # az vm image list --all \
        #     --publisher 'Debian' --offer 'debian-10' --sku '10' \
        #     --query "[?publisher == 'Debian' && offer == 'debian-10'].{ sku: sku, version: version }" --output table
        vm_image='Debian:debian-10:10-gen2:0.20201023.432'
        ;;

    'ubuntu:18.04')
        # az vm image list --all \
        #     --publisher 'Canonical' --offer 'UbuntuServer' --sku '18' \
        #     --query "[?publisher == 'Canonical' && offer == 'UbuntuServer'].{ sku: sku, version: version }" --output table
        vm_image='Canonical:UbuntuServer:18_04-lts-gen2:18.04.202010140'
        ;;

    'ubuntu:20.04')
        # Different offer because UbuntuServer offer does not have 20.04 yet.
        #
        # Ref: https://github.com/Azure/azure-cli/issues/13320#issuecomment-649867249
        #
        # az vm image list --all \
        #     --publisher 'Canonical' --offer '0001-com-ubuntu-server-focal' --sku '20' \
        #     --query "[?publisher == 'Canonical' && offer == '0001-com-ubuntu-server-focal'].{ sku: sku, version: version }" --output table
        vm_image='Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:20.04.202010260'
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac


echo 'Generating ssh key...' >&2
# https://docs.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys#supported-ssh-key-formats
ssh-keygen -t rsa -b 4096 -f vm-ssh-key -N ''
echo 'Generated ssh key' >&2


common_resource_name="${run_id//:/-}"
common_resource_name="${common_resource_name//./-}"
echo "common_resource_name: $common_resource_name" >&2

resource_tag="run_id=$run_id"
echo "resource_tag: $resource_tag" >&2


# `az resource list` has `--tag` to filter, but it cannot be combined with `--resource-group`,
# so query with `--resource-group` and filter for tags client-side.
#
# Also, sometimes deleting resources fails because `az resource delete` doesn't respect inter-resource dependencies.
# So keep trying it in a loop as long as there are still resources that match.
#
# ShellCheck warns the variables will be expanded when this string is parsed rather than when it executes,
# but that is the intention to begin with.
# shellcheck disable=SC2064
#
# ShellCheck thinks `ids` is referenced before being defined, which is not true.
# It's probably not taking the escaping into account.
# shellcheck disable=SC2154
trap "
    set +eo pipefail

    rm -f package.zip vm-ssh-key vm-ssh-key.pub *.deb *.rpm

    echo 'Deleting resources...' >&2
    while :; do \
        ids=\"\$(
            az resource list --resource-group '$AZURE_RESOURCE_GROUP_NAME' |
                jq -r '.[] | select(.tags.run_id == \"$run_id\").id'
        )\"
        if [ -z \"\$ids\" ]; then
            break
        else
            <<< \"\$ids\" xargs az resource delete --ids >/dev/null
        fi

        sleep 1
        echo 'Retrying...' >&2
    done

    if [ -n \"\${vm_os_disk:-}\" ]; then
        az resource delete --ids \"\$vm_os_disk\"
    fi

    echo 'Deleted resources' >&2
" EXIT


# Creating an IoT Hub is slow, so parallelize it with prepping the VM.

(
    echo 'Creating IoT Hub...' >&2
    iot_hub_resource_id="$(
        az iot hub create \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
            --name "$common_resource_name" \
            --sku 'S1' --unit 1 --partition-count 2 \
            --query 'id' --output tsv
    )"
    # `az iot hub create` doesn't have `--tags`, so tag it manually.
    #
    # Ref: https://github.com/Azure/azure-cli/issues/13497
    >/dev/null az resource tag \
        --ids "$iot_hub_resource_id" \
        --tags "$resource_tag"
    echo 'Created IoT Hub' >&2


    case "$test_name" in
        'manual-symmetric-key')
            echo 'Creating IoT device...' >&2
            iot_device_id="$common_resource_name-01"
            manual_symmetric_key="$(
                az iot hub device-identity create \
                    --hub-name "$common_resource_name" \
                    --device-id "$iot_device_id" \
                    --auth-method 'shared_private_key' \
                    --query 'authentication.symmetricKey.primaryKey' --output tsv
            )"
            echo 'Created IoT device' >&2

            echo 'Generating config files...' >&2

            >keyd.toml cat <<-EOF
[aziot_keys]
homedir_path = "/var/lib/aziot/keyd"

[preloaded_keys]
device-id = "file:///var/secrets/aziot/keyd/device-id"
EOF

            >certd.toml cat <<-EOF
homedir_path = "/var/lib/aziot/certd"

[cert_issuance]

[preloaded_certs]
EOF

            >identityd.toml cat <<-EOF
hostname = "$common_resource_name"
homedir = "/var/lib/aziot/identityd"

[provisioning]
always_reprovisioning_on_startup = true
source = "manual"
iothub_hostname = "$common_resource_name.azure-devices.net"
device_id = "$iot_device_id"

[provisioning.authentication]
method = "sas"
device_id_pk = "device-id"
EOF

            >device-id base64 -d <<< "$manual_symmetric_key"

            echo 'Generated config files' >&2
            ;;

        *)
            echo "Unsupported test $1" >&2
            exit 1
            ;;
    esac

    >testmodule.toml cat <<-EOF
[[principal]]
uid = 1000
name = "testmodule"
idtype = ["module"]
EOF
) &


echo 'Creating NSG...' >&2
nsg_id="$(
    az network nsg create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$common_resource_name" \
        --tags "$resource_tag" \
        --query 'id' --output tsv
)"
echo 'Created NSG' >&2

echo 'Querying public IP...' >&2
self_ip="$(curl -L 'https://ipinfo.io/ip')"
echo 'Queried public IP' >&2

echo 'Creating allow-ssh rule in NSG...' >&2
>/dev/null az network nsg rule create \
    --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
    --nsg-name "$common_resource_name" \
    --name 'ssh' \
    --priority 1000 \
    --access 'Allow' --direction 'Inbound' --protocol 'Tcp' \
    --destination-port-ranges '22' \
    --source-address-prefixes "$self_ip/32"
echo 'Created allow-ssh rule in NSG' >&2


echo 'Creating VM...' >&2
vm_id="$(
    </dev/null az vm create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$common_resource_name" \
        --image "$vm_image" \
        --size 'Standard_B1s' \
        --admin-username 'aziot' \
        --authentication-type 'ssh' \
        --ssh-key-values "$PWD/vm-ssh-key.pub" \
        --nsg "$nsg_id" \
        --vnet-name "$common_resource_name" \
        --enable-agent 'false' \
        --tags "$resource_tag" \
        --query 'id' --output tsv
)"
vm="$(az vm show --ids "$vm_id" --show-details)"
vm_public_ip="$(<<< "$vm" jq -r '.publicIps')"
# Get this ID explicitly so that the exit trap can delete it explicitly.
# `az resource list` apparently is cached by ARM and often doesn't return the disk,
# so it would end up not being deleted by the exit trap if the trap just relied on `az resource list`.
vm_os_disk="$(<<< "$vm" jq -r '.storageProfile.osDisk.managedDisk.id')"
echo 'Created VM' >&2

echo 'Waiting for VM to respond to ssh...' >&2
for retry in {0..60}; do
    sleep 10
    if timeout 5 ssh -o StrictHostKeyChecking=no -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" echo 'VM is up' >&2; then
        echo $?
        break
    else
        echo $?
    fi

    sleep 1
done
if ! ssh -o StrictHostKeyChecking=no -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" echo 'VM is up' >&2; then
    echo 'VM did not come up in time.' >&2
    exit 1
fi


echo 'Updating VM...' >&2
case "$OS" in
    centos:*)
        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo yum -y update

            # The test needs jq
            sudo yum -y install epel-release
        '
        ;;

    debian:*|ubuntu:*)
        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo apt-get update -y
            sudo apt-get upgrade -y
        '
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac
echo 'Updated VM' >&2

echo 'Rebooting VM...' >&2
ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" 'sudo reboot' || :
echo 'Rebooted VM' >&2

echo 'Waiting for VM to respond to ssh...' >&2
# ShellCheck warns that `retry` is unused, but that's okay.
# shellcheck disable=SC2034
for retry in {0..60}; do
    sleep 10
    if timeout 5 ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" echo 'VM is up' >&2; then
        echo $?
        break
    else
        echo $?
    fi

    sleep 1
done
if ! ssh -o StrictHostKeyChecking=no -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" echo 'VM is up' >&2; then
    echo 'VM did not come up in time.' >&2
    exit 1
fi


echo 'Installing package...' >&2
case "$OS" in
    centos:*)
        scp -i "$PWD/vm-ssh-key" "$package" "aziot@$vm_public_ip:/home/aziot/aziot-identity-service.rpm"

        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo yum install -y bc curl jq
            sudo yum -y install /home/aziot/aziot-identity-service.rpm

            sudo systemctl start aziot-{key,cert,identity}d.socket
        '

        ;;

    debian:*|ubuntu:*)
        scp -i "$PWD/vm-ssh-key" "$package" "aziot@$vm_public_ip:/home/aziot/aziot-identity-service.deb"

        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo apt-get install -y bc curl jq
            sudo apt-get install -y /home/aziot/aziot-identity-service.deb
        '
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac
echo 'Installed package' >&2


echo 'Waiting for IoT Hub to finish being created...' >&2
# ShellCheck warns the `jobs` invocation is not quoted, but that's intentional so that it's word-split.
# shellcheck disable=SC2046
wait $(jobs -pr)
echo 'Created IoT Hub' >&2


echo 'Configuring package...' >&2

scp -i "$PWD/vm-ssh-key" ./*.toml "aziot@$vm_public_ip:/home/aziot/"

ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
    set -euxo pipefail

    sudo mv /home/aziot/keyd.toml /etc/aziot/keyd/config.toml
    sudo chown aziotks:aziotks /etc/aziot/keyd/config.toml
    sudo chmod 0600 /etc/aziot/keyd/config.toml

    sudo mv /home/aziot/certd.toml /etc/aziot/certd/config.toml
    sudo chown aziotcs:aziotcs /etc/aziot/certd/config.toml
    sudo chmod 0600 /etc/aziot/certd/config.toml

    sudo mv /home/aziot/identityd.toml /etc/aziot/identityd/config.toml
    sudo chown aziotid:aziotid /etc/aziot/identityd/config.toml
    sudo chmod 0600 /etc/aziot/identityd/config.toml

    sudo mv /home/aziot/testmodule.toml /etc/aziot/identityd/config.d/testmodule.toml
    sudo chown aziotid:aziotid /etc/aziot/identityd/config.d/testmodule.toml
    sudo chmod 0600 /etc/aziot/identityd/config.d/testmodule.toml

    sudo usermod -aG aziotcs aziot
    sudo usermod -aG aziotks aziot
    sudo usermod -aG aziotid aziot
'

if [ -f device-id ]; then
    scp -i "$PWD/vm-ssh-key" device-id "aziot@$vm_public_ip:/home/aziot/"
    ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
        set -euxo pipefail

        sudo mkdir -p /var/secrets/aziot/keyd
        sudo chown aziotks:aziotks /var/secrets/aziot/keyd
        sudo chmod 0700 /var/secrets/aziot/keyd

        sudo mv /home/aziot/device-id /var/secrets/aziot/keyd/device-id
        sudo chown aziotks:aziotks /var/secrets/aziot/keyd/device-id
        sudo chmod 0600 /var/secrets/aziot/keyd/device-id
    '
fi

echo 'Configured package' >&2


echo 'Running test...' >&2
scp -i "$PWD/vm-ssh-key" "$GITHUB_WORKSPACE/ci/iothub-get-twin.sh" "aziot@$vm_public_ip:/home/aziot/"
ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" "
    set -euxo pipefail

    sudo systemctl enable aziot-identityd
    sudo systemctl start aziot-identityd

    # \"Starting server...\" implies provisioning is done.
    #
    # Use process substitution for the journalctl | grep so that the command exits as soon as it emits one line of output
    # rather than waiting for the timeout to expire.
    #
    # Pipe the output of head through grep so as to exit with non-zero if the head didn't output anything,
    # ie the inner grep didn't find the expected line.
    head -n 1 < <(
        sudo timeout 60 journalctl --unit aziot-identityd --all --follow |
            tee /dev/stderr |
            grep --line-buffered 'Starting server\\.\\.\\.'
    ) |
        grep -q .

    # Get device identity and use it to get device twin
    device_identity=\"\$(
        sudo curl --unix-socket '/run/aziot/identityd.sock' \\
            -X POST -H 'content-type: application/json' --data-binary '{ \"type\": \"\" }' \\
            'http://foo/identities/device?api-version=2020-09-01'
    )\"
    printf 'Device identity: %s\n' \"\$device_identity\" >&2

    if [ \"\$(<<< \"\$device_identity\" jq -r '.type')\" != 'aziot' ]; then
        echo 'Expected .type to be aziot' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$device_identity\" jq -r '.spec.hubName')\" != '$common_resource_name.azure-devices.net' ]; then
        echo 'Expected .spec.hubName to be $common_resource_name.azure-devices.net' >&2
        exit 1
    fi

    device_twin=\"\$(~/iothub-get-twin.sh \"\$device_identity\")\"
    printf 'Device twin: %s\n' \"\$device_twin\" >&2

    module_identity=\"\$(
        curl --unix-socket '/run/aziot/identityd.sock' \\
            'http://foo/identities/identity?api-version=2020-09-01'
    )\"
    printf '%s\n' \"\$module_identity\" >&2

    if [ \"\$(<<< \"\$module_identity\" jq -r '.type')\" != 'aziot' ]; then
        echo 'Expected .type to be aziot' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$module_identity\" jq -r '.spec.hubName')\" != '$common_resource_name.azure-devices.net' ]; then
        echo 'Expected .spec.hubName to be $common_resource_name.azure-devices.net' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$module_identity\" jq -r '.spec.moduleId')\" != 'testmodule' ]; then
        echo 'Expected .spec.moduleId to be testmodule' >&2
        exit 1
    fi

    module_twin=\"\$(~/iothub-get-twin.sh \"\$module_identity\")\"
    printf 'Module twin: %s\n' \"\$module_twin\" >&2
"
echo 'Test passed.' >&2
