#!/bin/bash


. "$GITHUB_WORKSPACE/ci/e2e-tests/suite-common.sh"


test_name="$1"


# Test ID. Used as resource tag for all Azure resources created in this test.
test_id="${BRANCH:-unknown}:$GITHUB_RUN_ID:$GITHUB_RUN_NUMBER:$OS:$test_name"
echo "test_id: $test_id" >&2

# Common name for all test-level Azure resources
test_common_resource_name="$(printf '%s' "$test_id" | tr -C 'a-z0-9' '-')"
echo "test_common_resource_name: $test_common_resource_name" >&2

# Temp directory used as scratch space to store the downloaded package from GitHub
# and the config files for the package that are scp'd to the test VM.
working_directory="/tmp/iot-identity-service-e2e-tests-$test_common_resource_name"
echo "working_directory: $working_directory" >&2

echo 'Installing test tools...' >&2
case "$OS" in
    centos:*|platform:el*)

        ;;

    debian:*|ubuntu:*)
        distributor_id=$(lsb_release -is)
        release=$(lsb_release -rs)
        wget "https://packages.microsoft.com/config/${distributor_id,,}/$release/packages-microsoft-prod.deb" \
            -O packages-microsoft-prod.deb
        sudo dpkg -i packages-microsoft-prod.deb
        rm packages-microsoft-prod.deb
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

        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https dotnet-sdk-6.0 azure-functions-core-tools-4    
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac
echo 'Installed test tools' >&2    