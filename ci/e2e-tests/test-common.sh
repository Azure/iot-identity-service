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
