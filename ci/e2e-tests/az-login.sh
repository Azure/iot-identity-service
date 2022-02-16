#!/bin/bash


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

az config set core.collect_telemetry=no
