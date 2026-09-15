#!/bin/bash


# Suite ID. Used as resource tag for all Azure resources created in this suite.
suite_id="${BRANCH:-unknown}:$GITHUB_RUN_ID:$GITHUB_RUN_NUMBER"
echo "suite_id: $suite_id" >&2

# Common name for all suite-level Azure resources
suite_common_resource_name="$(printf '%s' "$suite_id" | tr -C 'a-z0-9' '-')"
echo "suite_common_resource_name: $suite_common_resource_name" >&2

# Variables related to the DPS custom allocation policy
dps_allocation_function_name='DpsCustomAllocation'
dps_allocation_functionapp_name="alloc-app-${suite_common_resource_name}"
foo_devices_iot_hub="${suite_common_resource_name}-foo-devices"
dps_allocation_storage_account="$(printf '%s' "$suite_id" | tr '[:upper:]' '[:lower:]' | tr -d -C 'a-z0-9')"
# storage accounts names can't be longer than 24 chars; truncate (from the front of the string) if necessary
if [[ ${#dps_allocation_storage_account} -gt 24 ]]; then
    dps_allocation_storage_account="${dps_allocation_storage_account: -24}"
fi
