// Copyright (c) Microsoft. All rights reserved.
#include "hsm_constants.h"

/* HSM C misc constants */
const char* const EDGE_STORE_NAME = "edgelet";
const char* const EDGELET_IDENTITY_SAS_KEY_NAME = "edgelet-identity";

// Note: `iotedge check` has a warning message that references the 90-day expiry in `fn settings_certificates`.
// Update that when changing the value here.
const uint64_t CA_VALIDITY = 90 * 24 * 3600; // 90 days
