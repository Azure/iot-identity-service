// Copyright (c) Microsoft. All rights reserved.

use super::Checker;

/// Tries to unwrap an option, early-returning with
/// `return Ok(CheckResult::Skipped)` if the option is None.
macro_rules! unwrap_or_skip {
    ($opt:expr) => {{
        use crate::internal::check::CheckResult;

        match $opt {
            Some(val) => val,
            None => return Ok(CheckResult::Skipped),
        }
    }};
}

mod cert_expiry;
mod certs_preloaded;
mod daemons_running;
mod host_connect_dps_endpoint;
mod host_connect_iothub;
mod host_local_time;
mod hostname;
mod up_to_date_configs;
mod well_formed_configs;

pub fn all_checks() -> Vec<(&'static str, Vec<Box<dyn Checker>>)> {
    // DEVNOTE: keep ordering consistent. Later tests may depend on earlier tests.
    vec![
        ("Configuration checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.extend(well_formed_configs::well_formed_configs());
            v.push(Box::new(up_to_date_configs::UpToDateConfigs::default()));
            v.push(Box::new(hostname::Hostname::default()));
            // TODO: add aziotd version info to https://github.com/Azure/azure-iotedge
            // v.push(Box::new(aziotd_version::AziotdVersion::default()));
            v.push(Box::new(host_local_time::HostLocalTime::default()));
            v.extend(cert_expiry::cert_expirations());
            v.push(Box::new(certs_preloaded::CertsPreloaded::default()));
            v
        }),
        ("Connectivity checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.extend(host_connect_iothub::host_connect_iothub_checks());
            v.extend(daemons_running::daemons_running());
            v.push(Box::new(
                host_connect_dps_endpoint::HostConnectDpsEndpoint::default(),
            ));
            v
        }),
    ]
}
