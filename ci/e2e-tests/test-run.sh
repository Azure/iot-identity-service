#!/bin/bash

# Usage:
#
# ./ci/e2e-tests/test-run.sh <test_name>
#
# See https://github.com/Azure/iot-identity-service/blob/main/docs-dev/e2e-tests.md for details of some env vars that need to be defined.
#
# <test_name>:
#     manual-symmetric-key

set -euo pipefail


echo "$0 $*" >&2


GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"

. "$GITHUB_WORKSPACE/ci/e2e-tests/test-common.sh"


. "$GITHUB_WORKSPACE/ci/e2e-tests/az-login.sh"

source "$GITHUB_WORKSPACE/ci/e2e-tests/helper-functions.sh"

get_package() {
    if [ -n "${PACKAGE:-}" ]; then
        echo "Using package specified by PACKAGE" >&2
        printf '%s\n' "$PACKAGE"
        return
    fi

    # The download-artifact action does not have a way to download artifacts from other workflows.
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
    # Ref: https://docs.github.com/en/rest/reference/actions#list-workflow-runs
    echo "Getting latest workflow run's artifacts URL..." >&2
    artifacts_url='null'

    # GitHub API calls may fail if too many other tests make the same call concurrently.
    # Allow a few retries before failing.
    set +e
    for retry in {0..3}; do
        if [ "$retry" != '0' ]; then
            sleep 10
        fi

        artifacts_url="$(
            github_curl -L \
                -H 'accept: application/vnd.github.v3+json' \
                "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/workflows/packages.yaml/runs?branch=${BRANCH//\//%2f}&event=push&status=success" |
                jq -r '.workflow_runs[0].artifacts_url'
        )"

        if [ -n "$artifacts_url" ] && [ "$artifacts_url" != 'null' ]; then
            break
        fi
    done
    set -e

    if [ "$artifacts_url" = 'null' ]; then
        echo "No successfully-concluded packages workflow found for branch $BRANCH" >&2
        exit 1
    fi
    echo "Artifacts URL: $artifacts_url" >&2

    case "$OS" in
        'debian:11')
            artifact_name='debian-11-slim'
            ;;

        'platform:el8')
            artifact_name='redhat-ubi8-latest'
            ;;

        'platform:el9')
            artifact_name='redhat-ubi9-latest'
            ;;

        'ubuntu:20.04')
            artifact_name='ubuntu-20.04'
            ;;

        'ubuntu:22.04')
            artifact_name='ubuntu-22.04'
            ;;

        *)
            echo "Unsupported OS $OS" >&2
            exit 1
            ;;
    esac
    artifact_name="packages_${artifact_name}_amd64"

    echo 'Getting artifact download URL...' >&2
    artifact_download_url=""

    set +e
    for retry in {0..3}; do
        if [ "$retry" != '0' ]; then
            sleep 10
        fi

        artifact_download_url="$(
            github_curl -L \
                -H 'accept: application/vnd.github.v3+json' \
                "$artifacts_url" |
                jq \
                    --arg artifact_name "$artifact_name" \
                    -r \
                    '.artifacts[] | select(.name == $artifact_name) | .archive_download_url'
        )"

        if [ -n "$artifact_download_url" ] && [ "$artifact_download_url" != 'null' ]; then
            break
        fi
    done
    set -e

    if [ -z "$artifact_download_url" ]; then
        echo "Could not find artifact for OS $OS" >&2
        exit 1
    fi
    echo "Artifact download URL: $artifact_download_url" >&2

    echo 'Downloading artifact...' >&2
    set +e
    for retry in {0..3}; do
        if [ "$retry" != '0' ]; then
            sleep 10
        fi

        github_curl -L \
            -o package.zip \
            "$artifact_download_url"

        # Check if a valid zipfile was downloaded.
        unzip -t package.zip >& /dev/null

        if [ "$?" == '0' ]; then
            break
        fi
    done
    set -e
    echo 'Downloaded artifact' >&2


    echo 'Extracting package...' >&2
    case "$OS" in
        'debian:11')
            unzip -j package.zip 'debian11/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        'platform:el8')
            unzip -j package.zip 'el8/amd64/aziot-identity-service-*.x86_64.rpm' -x '*-debuginfo-*.rpm' '*-devel-*.rpm' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service-*.x86_64.rpm
            ;;

        'platform:el9')
            unzip -j package.zip 'el9/amd64/aziot-identity-service-*.x86_64.rpm' -x '*-debuginfo-*.rpm' '*-devel-*.rpm' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service-*.x86_64.rpm
            ;;

        'ubuntu:20.04')
            unzip -j package.zip 'ubuntu2004/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        'ubuntu:22.04')
            unzip -j package.zip 'ubuntu2204/amd64/aziot-identity-service_*_amd64.deb' >&2
            printf '%s/%s\n' "$PWD" aziot-identity-service_*_amd64.deb
            ;;

        *)
            echo "Unsupported OS $OS" >&2
            exit 1
            ;;
    esac
    echo 'Extracted package' >&2
}


mkdir -p "$working_directory"
cd "$working_directory"


package="$(get_package)"
echo "Using package at [$package]" >&2
if ! [ -f "$package" ]; then
    echo 'Could not find package file' >&2
    exit 1
fi


case "$test_name" in
    dps-*)
        dps_scope_id="$(
            az iot dps show \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                --name "$suite_common_resource_name" |
            jq '.properties.idScope' -r
        )"
        ;;
esac


expected_assigned_hub_name=$suite_common_resource_name
case "$test_name" in
    'manual-symmetric-key')
        echo 'Creating IoT device...' >&2
        manual_symmetric_key="$(
            az iot hub device-identity create \
                --login "$(
                    # Use --login with connection string rather than --hub-name with Hub name
                    #
                    # This is because `device-identity create` internally lists all the Hubs in the subscription,
                    # and for some reason ARM loves to return an empty list for it. Running `az iot hub list` concurrently
                    # shows the same thing, so it's definitely not a problem with az but with ARM itself.
                    # Meanwhile `az iot hub show` shows the supposedly non-existent Hub just fine.
                    az iot hub connection-string show \
                        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                        --hub-name "$suite_common_resource_name" \
                        --query 'connectionString' --output tsv
                )" \
                --device-id "$test_common_resource_name" \
                --auth-method 'shared_private_key' \
                --query 'authentication.symmetricKey.primaryKey' --output tsv
        )"
        echo 'Created IoT device' >&2

        echo 'Generating config files...' >&2

        >config.toml cat <<-EOF
hostname = "$test_common_resource_name"

[provisioning]
source = "manual"
iothub_hostname = "$suite_common_resource_name.azure-devices.net"
device_id = "$test_common_resource_name"

[provisioning.authentication]
method = "sas"
device_id_pk = { value = "$manual_symmetric_key" }
EOF
        ;;

    'manual-x509')
        echo 'Creating self-signed root CA' >&2
        openssl req \
            -new \
            -x509 \
            -newkey rsa:4096 -keyout device-id-root.key.pem -nodes \
            -subj "/CN=aziot_root_ca_cert_e2e_test" \
            -days 30 \
            -sha256 \
            -out device-id-root.pem

        echo 'Generating CSR for device ID cert and signing it with the root CA to get the device id cert.' >&2
        openssl req \
            -newkey rsa:2048 -keyout device-id.key.pem -nodes \
            -out device-id.csr \
            -days 1 \
            -subj="/CN=$test_common_resource_name"
        openssl x509 -req \
            -in device-id.csr \
            -CA device-id-root.pem -CAkey device-id-root.key.pem \
            -out device-id.pem \
            -days 365 -CAcreateserial

        thumbprint=$(< device-id.pem openssl x509 -fingerprint -noout | grep -Po 'Fingerprint=\K.*' | tr -d ':')

        echo 'Creating IoT device...' >&2
        az iot hub device-identity create \
            --login "$(
                # See previous invocation of `device-identity create` for why this uses
                # --login with connection string rather than --hub-name with Hub name.
                az iot hub connection-string show \
                    --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                    --hub-name "$suite_common_resource_name" \
                    --query 'connectionString' --output tsv
            )" \
            --device-id "$test_common_resource_name" \
            --auth-method 'x509_thumbprint' \
            --primary-thumbprint "$thumbprint" \
            --secondary-thumbprint "$thumbprint"
        echo 'Created IoT device' >&2

        echo 'Generating config files...' >&2

        >config.toml cat <<-EOF
hostname = "$test_common_resource_name"

[provisioning]
source = "manual"
iothub_hostname = "$suite_common_resource_name.azure-devices.net"
device_id = "$test_common_resource_name"

[provisioning.authentication]
method = "x509"
identity_cert = "file:///var/secrets/aziot/certd/device-id.pem"
identity_pk = "file:///var/secrets/aziot/keyd/device-id.key.pem"
EOF
        ;;

    'dps-symmetric-key')
        expected_assigned_hub_name="$foo_devices_iot_hub"
        webhook_url="$(
            az functionapp function show \
                --function-name $dps_allocation_function_name \
                --resource-group $AZURE_RESOURCE_GROUP_NAME \
                --query "invokeUrlTemplate" --output tsv \
                --name $dps_allocation_functionapp_name
        )"

        echo 'Creating symmetric key enrollment group in DPS...' >&2
        dps_symmetric_key="$(
            az iot dps enrollment-group create \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                --dps-name "$suite_common_resource_name" \
                --enrollment-id "$test_common_resource_name" \
                --iot-hubs "$suite_common_resource_name.azure-devices.net $expected_assigned_hub_name.azure-devices.net" \
                --query 'attestation.symmetricKey.primaryKey' --output tsv \
                --allocation-policy custom \
                --api-version 2021-06-01 \
                --webhook-url $webhook_url
        )"
        echo 'Created symmetric key enrollment group in DPS.' >&2

        echo 'Deriving individual device key...' >&2
        keybytes="$(echo "$dps_symmetric_key" | base64 --decode | xxd -p -u -c 1000)"
        derived_device_key="$(printf '%s' "$test_common_resource_name" | openssl sha256 -mac HMAC -macopt "hexkey:$keybytes" -binary | base64 -w 0)"

        echo 'Generating config files...' >&2
        >payload.json cat <<-EOF
{
    "modelId": "foo 2022"
}
EOF
        >config.toml cat <<-EOF
hostname = "$test_common_resource_name"

[provisioning]
source = "dps"
global_endpoint = "https://global.azure-devices-provisioning.net/"
id_scope = "$dps_scope_id"
payload = { uri = "file:///etc/aziot/payload.json" }

[provisioning.attestation]
method = "symmetric_key"
registration_id = "$test_common_resource_name"
symmetric_key = { value = "$derived_device_key" }
EOF
        echo 'Generated config files.' >&2
        ;;

    'dps-x509')
        echo 'Creating self-signed root CA' >&2
        openssl req \
            -new \
            -x509 \
            -newkey rsa:4096 -keyout device-id-root.key.pem -nodes \
            -subj "/CN=aziot_root_ca_cert_e2e_test" \
            -days 30 \
            -sha256 \
            -out device-id-root.pem

        echo 'Uploading root CA to DPS...' >&2
        az iot dps certificate create \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
            --dps-name "$suite_common_resource_name" \
            --certificate-name "$test_common_resource_name" \
            --path device-id-root.pem
        echo 'Uploaded root CA to DPS' >&2

        echo 'Fetching first etag for verification code request...' >&2
        etag="$(
            az iot dps certificate show \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                --dps-name "$suite_common_resource_name" \
                --certificate-name "$test_common_resource_name" \
                --query etag --output tsv
        )"

        echo 'Generating verification code and saving new etag...' >&2
        cloud_certificate="$(
            az iot dps certificate generate-verification-code \
                --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
                --dps-name "$suite_common_resource_name" \
                --certificate-name "$test_common_resource_name" \
                --etag "$etag"
        )"
        etag="$(<<< "$cloud_certificate" jq '.etag' -r)"
        verification_code="$(<<< "$cloud_certificate" jq '.properties.verificationCode' -r)"

        echo 'Generating CSR for verification cert and signing it with the root CA to get the verification cert.' >&2
        openssl req \
            -newkey rsa:2048 -keyout device-id-root-verify.key.pem -nodes \
            -out device-id-root-verify.csr \
            -days 1 \
            -subj "/CN=${verification_code}"

        openssl x509 -req \
            -in device-id-root-verify.csr \
            -CA device-id-root.pem -CAkey device-id-root.key.pem \
            -out device-id-root-verify.pem \
            -days 365 -CAcreateserial

        echo 'Uploading verification cert to DPS...' >&2
        az iot dps certificate verify \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
            --dps-name "$suite_common_resource_name" \
            --certificate-name "$test_common_resource_name" \
            --path device-id-root-verify.pem \
            --etag "$etag"
        echo 'Uploaded verification cert to DPS' >&2

        echo 'Creating x509 enrollment group in DPS...' >&2
        az iot dps enrollment-group create \
            --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
            --dps-name "$suite_common_resource_name" \
            --enrollment-id "$test_common_resource_name" \
            --ca-name "$test_common_resource_name" \
            --iot-hub-host-name "$suite_common_resource_name.azure-devices.net"
        echo 'Created x509 enrollment group in DPS.' >&2

        echo 'Generating CSR for device ID cert and signing it with the root CA to get the device id cert.' >&2
        openssl req \
            -newkey rsa:2048 -keyout device-id.key.pem -nodes \
            -out device-id.csr \
            -days 1 \
            -subj="/CN=$test_common_resource_name"
        openssl x509 -req \
            -in device-id.csr \
            -CA device-id-root.pem -CAkey device-id-root.key.pem \
            -out device-id.pem \
            -days 365 -CAcreateserial

        echo 'Generating config files...' >&2

        >config.toml cat <<-EOF
hostname = "$test_common_resource_name"

[provisioning]
source = "dps"
global_endpoint = "https://global.azure-devices-provisioning.net/"
id_scope = "$dps_scope_id"

[provisioning.attestation]
method = "x509"
registration_id = "$test_common_resource_name"
identity_cert = "file:///var/secrets/aziot/certd/device-id.pem"
identity_pk = "file:///var/secrets/aziot/keyd/device-id.key.pem"
EOF
        ;;

    *)
        echo "Unsupported test $1" >&2
        exit 1
        ;;
esac

>99-testmodule.toml cat <<-EOF
[[principal]]
uid = 1000
name = "testmodule"
idtype = ["module"]
EOF

echo 'Generated config files' >&2


echo 'Creating NSG...' >&2
nsg_id="$(
    az network nsg create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$test_common_resource_name" \
        --tags "suite_id=$suite_id" "test_id=$test_id" \
        --query 'NewNSG.id' --output tsv
)"
echo 'Created NSG' >&2

echo 'Querying public IP...' >&2
self_ip="$(wget -qO- https://ipecho.net/plain ; echo)"
echo 'Queried public IP' >&2

echo 'Creating allow-ssh rule in NSG...' >&2
>/dev/null az network nsg rule create \
    --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
    --nsg-name "$test_common_resource_name" \
    --name 'ssh' \
    --priority 1000 \
    --access 'Allow' --direction 'Inbound' --protocol 'Tcp' \
    --destination-port-ranges '22' \
    --source-address-prefixes "$self_ip/32"
echo 'Created allow-ssh rule in NSG' >&2


echo 'Creating VM...' >&2

# VM image as taken by `az vm create` is specified as the URN, which is `$publisher:$offer:$sku:$version`.
# We set the version to `latest` so that we don't have to keep updating it.
#
# Commented-out commands show how to query the SKU if needed to update. When possible, use the SKU that has
# a `-gen2` suffix so that it creates a Gen 2 VM instead of a Gen 1 VM. (The VM generation is determined by the SKU.)
#
# `--publisher` and `--offer` are useful to filter server-side. But they filter as substrings and return many irrelevant matches,
# so the commands also filter for exact matches using `--query`. `--sku` is left as a substring match so that the query doesn't have to
# give a specific minor version.
#
# Choice of publisher is determined by
# https://docs.microsoft.com/en-us/troubleshoot/azure/cloud-services/support-linux-open-source-technology
case "$OS" in
    'debian:11')
        # Not listed on the docs.microsoft.com page, but credativ doesn't publish Debian 10+ images.
        #
        # az vm image list --all \
        #     --publisher 'Debian' --offer 'debian-11' --sku '11-gen2' \
        #     --query "[?publisher == 'Debian' && offer == 'debian-11'].{ sku: sku, version: version, urn: urn }" --output table
        vm_image='Debian:debian-11:11-gen2:latest'
        ;;

    'platform:el8')
        # az vm image list --all \
        #     --publisher 'almalinux' --offer 'almalinux' --sku '8_4-gen2' \
        #     --query "[?publisher == 'almalinux' && offer == 'almalinux'].{ sku: sku, version: version, urn: urn }" --output table
        #
        # When changing this, accept the VM image terms with
        #
        #    az vm image terms accept --urn "$vm_image"
        #
        # The Azure SP does not have permissions to do this. Use your regular Azure account.
        vm_image='almalinux:almalinux:8_4-gen2:latest'
        ;;

     'platform:el9')
        # az vm image list --all \
        #     --publisher 'RedHat' --offer 'RHEL' --sku '9-lvm-gen2' \
        #     --query "[?publisher == 'RedHat' && offer == 'RHEL'].{ sku: sku, version: version, urn: urn }" --output table
        #
        # When changing this, accept the VM image terms with
        #
        #    az vm image terms accept --urn "$vm_image"
        #
        # The Azure SP does not have permissions to do this. Use your regular Azure account.
        vm_image='RedHat:RHEL:9-lvm-gen2:latest'
        ;;

    'ubuntu:20.04')
        # Canonical switched to a different offer for 20.04 and above.
        #
        # Ref: https://github.com/Azure/azure-cli/issues/13320#issuecomment-649867249
        # Ref: https://github.com/Azure/azure-cli/issues/13320#issuecomment-756360943
        #
        # az vm image list --all \
        #     --publisher 'Canonical' --offer '0001-com-ubuntu-server-focal' --sku '20' \
        #     --query "[?publisher == 'Canonical' && offer == '0001-com-ubuntu-server-focal'].{ sku: sku, version: version, urn: urn }" --output table
        vm_image='Canonical:0001-com-ubuntu-server-focal:20_04-lts-gen2:latest'
        ;;

    'ubuntu:22.04')
        # az vm image list --all \
        #     --publisher 'Canonical' --offer '0001-com-ubuntu-minimal-jammy' --sku 'minimal-22' \
        #     --query "[?publisher == 'Canonical' && offer == '0001-com-ubuntu-minimal-jammy'].{ sku: sku, version: version, urn: urn }" --output table
        vm_image='Canonical:0001-com-ubuntu-minimal-jammy:minimal-22_04-lts-gen2:latest'
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


vm_id="$(
    </dev/null az vm create \
        --resource-group "$AZURE_RESOURCE_GROUP_NAME" \
        --name "$test_common_resource_name" \
        --image "$vm_image" \
        --size 'Standard_B1s' \
        --admin-username 'aziot' \
        --authentication-type 'ssh' \
        --ssh-key-values "$PWD/vm-ssh-key.pub" \
        --nsg "$nsg_id" \
        --vnet-name "$test_common_resource_name" \
        --public-ip-sku 'Basic' \
        --enable-agent 'false' \
        --security-type 'Standard' \
        --tags "suite_id=$suite_id" "test_id=$test_id" \
        --query 'id' --output tsv
)"
vm="$(az vm show --ids "$vm_id" --show-details)"
vm_public_ip="$(<<< "$vm" jq -r '.publicIps')"
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
    debian:*|ubuntu:*)
        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            for retry in {0..3}; do
                if [ "$retry" != "0" ]; then
                    sleep 10
                fi

                sudo apt-get update -y

                if [ "$?" == "0" ]; then
                    break
                fi
            done

            set -euxo pipefail

            sudo DEBIAN_FRONTEND=noninteractive \
                apt-get \
                -o 'Dpkg::Options::=--force-confnew' \
                -o 'Dpkg::Options::=--force-confdef' \
                -y \
                --allow-downgrades \
                --allow-remove-essential \
                --allow-change-held-packages \
                upgrade
        '
        ;;

    platform:el*)
        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo yum -y clean all
            sudo yum -y makecache
            sudo yum -y update
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
    |platform:el*)
        scp -i "$PWD/vm-ssh-key" "$package" "aziot@$vm_public_ip:/home/aziot/aziot-identity-service.rpm"

        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            set -euxo pipefail

            sudo yum -y install bc curl jq perl
            sudo yum -y install /home/aziot/aziot-identity-service.rpm

            sudo systemctl start aziot-{key,cert,identity}d.socket
        '

        ;;

    debian:*|ubuntu:*)
        scp -i "$PWD/vm-ssh-key" "$package" "aziot@$vm_public_ip:/home/aziot/aziot-identity-service.deb"

        ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
            for retry in {0..3}; do
                if [ "$retry" != "0" ]; then
                    sleep 10
                fi

                sudo apt-get update -y

                if [ "$?" == "0" ]; then
                    break
                fi
            done

            set -euxo pipefail

            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y bc curl jq perl
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y /home/aziot/aziot-identity-service.deb
        '
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac
echo 'Installed package' >&2


echo 'Configuring package...' >&2

scp -i "$PWD/vm-ssh-key" ./config.toml ./99-testmodule.toml "aziot@$vm_public_ip:/home/aziot/"
if [ -f device-id.key.pem ] && [ -f device-id.pem ]; then
    scp -i "$PWD/vm-ssh-key" device-id.key.pem device-id.pem "aziot@$vm_public_ip:/home/aziot/"
fi
if [ -f payload.json ]; then
    scp -i "$PWD/vm-ssh-key" payload.json "aziot@$vm_public_ip:/home/aziot/"
fi

ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" '
    set -euxo pipefail

    sudo mv /home/aziot/config.toml /etc/aziot/
    sudo chown root:root /etc/aziot/config.toml
    sudo chmod 0600 /etc/aziot/config.toml
    if [ -f /home/aziot/payload.json ]; then
        sudo mv /home/aziot/payload.json /etc/aziot/
        sudo chown aziotid:aziotid /etc/aziot/payload.json
        sudo chmod 0600 /etc/aziot/payload.json
    fi

    sudo usermod -aG aziotcs aziot
    sudo usermod -aG aziotks aziot
    sudo usermod -aG aziotid aziot

    if [ -f /home/aziot/device-id.key.pem ] && [ -f /home/aziot/device-id.pem ]; then
        sudo mkdir -p /var/secrets/aziot/keyd
        sudo mkdir -p /var/secrets/aziot/certd

        sudo mv /home/aziot/device-id.key.pem /var/secrets/aziot/keyd/device-id.key.pem
        sudo chown aziotks:aziotks /var/secrets/aziot/keyd/device-id.key.pem
        sudo chmod 0600 /var/secrets/aziot/keyd/device-id.key.pem

        sudo mv /home/aziot/device-id.pem /var/secrets/aziot/certd/device-id.pem
        sudo chown aziotcs:aziotcs /var/secrets/aziot/certd/device-id.pem
        sudo chmod 0600 /var/secrets/aziot/certd/device-id.pem
    fi

    sudo mv /home/aziot/99-testmodule.toml /etc/aziot/identityd/config.d/
    sudo chown aziotid:aziotid /etc/aziot/identityd/config.d/99-testmodule.toml
    sudo chmod 0600 /etc/aziot/identityd/config.d/99-testmodule.toml
'

echo 'Configured package' >&2


echo 'Running test...' >&2
scp -i "$PWD/vm-ssh-key" "$GITHUB_WORKSPACE/ci/iothub-get-twin.sh" "aziot@$vm_public_ip:/home/aziot/"
ssh -i "$PWD/vm-ssh-key" "aziot@$vm_public_ip" "
    set -euxo pipefail

    sudo systemctl enable aziot-identityd

    sudo aziotctl config apply

    # \"Starting server...\" implies provisioning is done.
    #
    # Use process substitution for the journalctl | grep so that the command exits as soon as it emits one line of output
    # rather than waiting for the timeout to expire.
    #
    # Pipe the output of head through grep so as to exit with non-zero if the head didn't output anything,
    # ie the inner grep didn't find the expected line.
    head -n 1 < <(
        sudo timeout 60 journalctl --unit aziot-identityd --all --follow --since='1 min ago' |
            tee /dev/stderr |
            grep --line-buffered 'Starting server\\.\\.\\.'
    ) |
        grep -q .

    # Get device identity and use it to get device twin
    device_identity=\"\$(
        sudo curl --unix-socket '/run/aziot/identityd.sock' \\
            -X POST -H 'content-type: application/json' --data-binary '{ \"type\": \"\" }' \\
            'http://identityd.sock/identities/device?api-version=2020-09-01'
    )\"
    printf 'Device identity: %s\n' \"\$device_identity\" >&2

    if [ \"\$(<<< \"\$device_identity\" jq -r '.type')\" != 'aziot' ]; then
        echo 'Expected .type to be aziot' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$device_identity\" jq -r '.spec.hubName')\" != '$expected_assigned_hub_name.azure-devices.net' ]; then
        echo 'Expected .spec.hubName to be $expected_assigned_hub_name.azure-devices.net' >&2
        exit 1
    fi

    if [[ (\"$OS\" != 'ubuntu:22.04' && \"$OS\" != 'platform:el9') ||  \"$test_name\" != *'-x509'* ]]; then
        device_twin=\"\$(~/iothub-get-twin.sh \"\$device_identity\")\"
        printf 'Device twin: %s\n' \"\$device_twin\" >&2
    fi

    module_identity=\"\$(
        curl --unix-socket '/run/aziot/identityd.sock' \\
            'http://identityd.sock/identities/identity?api-version=2020-09-01'
    )\"
    printf '%s\n' \"\$module_identity\" >&2

    if [ \"\$(<<< \"\$module_identity\" jq -r '.type')\" != 'aziot' ]; then
        echo 'Expected .type to be aziot' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$module_identity\" jq -r '.spec.hubName')\" != '$expected_assigned_hub_name.azure-devices.net' ]; then
        echo 'Expected .spec.hubName to be $expected_assigned_hub_name.azure-devices.net' >&2
        exit 1
    fi

    if [ \"\$(<<< \"\$module_identity\" jq -r '.spec.moduleId')\" != 'testmodule' ]; then
        echo 'Expected .spec.moduleId to be testmodule' >&2
        exit 1
    fi

    if [[ (\"$OS\" != 'ubuntu:22.04' && \"$OS\" != 'platform:el9') ||  \"$test_name\" != *'-x509'* ]]; then
        module_twin=\"\$(~/iothub-get-twin.sh \"\$module_identity\")\"
        printf 'Module twin: %s\n' \"\$module_twin\" >&2
    fi
"
echo 'Test passed.' >&2
