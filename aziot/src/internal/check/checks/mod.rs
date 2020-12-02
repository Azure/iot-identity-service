use super::Checker;

mod prelude {
    pub use anyhow::{anyhow, Context, Error, Result};
    pub use serde::Serialize;

    pub use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerCfg, CheckerMeta};
}

mod host_local_time;
mod hostname;
mod well_formed_configs;

pub fn all_checks() -> Vec<(&'static str, Vec<Box<dyn Checker>>)> {
    // DEVNOTE: keep ordering consistent. Later tests may depend on earlier tests.
    vec![
        ("Configuration checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.extend(well_formed_configs::well_formed_configs());
            v.push(Box::new(hostname::Hostname::default()));
            // TODO: add aziot version info to https://github.com/Azure/azure-iotedge
            // v.push(Box::new(aziot_version::AziotVersion::default()));
            v.push(Box::new(host_local_time::HostLocalTime::default()));
            v
        }),
        ("Connectivity checks", vec![]),
    ]
}
