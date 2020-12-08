use super::Checker;

mod prelude {
    pub use anyhow::{anyhow, Context, Error, Result};
    pub use serde::Serialize;
    pub use tokio::prelude::*;

    pub use crate::internal::check::{
        CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared,
    };

    pub trait CertificateValidityExt {
        fn to_check_result(&self) -> Result<CheckResult>;
    }

    impl CertificateValidityExt for crate::internal::common::CertificateValidity {
        fn to_check_result(&self) -> Result<CheckResult> {
            let now = chrono::Utc::now();
            if self.not_before > now {
                Err(anyhow!(
                    "{} '{}' has not-before time {} which is in the future",
                    self.cert_name,
                    self.cert_id,
                    self.not_before,
                ))
            } else if self.not_after < now {
                Err(anyhow!(
                    "{} '{}' expired at {}",
                    self.cert_name,
                    self.cert_id,
                    self.not_after,
                ))
            } else if self.not_after < now + chrono::Duration::days(7) {
                Ok(CheckResult::Warning(anyhow!(
                    "{} '{}' will expire soon ({}, in {} days)",
                    self.cert_name,
                    self.cert_id,
                    self.not_after,
                    (self.not_after - now).num_days(),
                )))
            } else {
                Ok(CheckResult::Ok)
            }
        }
    }
}

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

mod certs_preloaded;
mod daemons_running;
mod host_connect_dps_endpoint;
mod host_local_time;
mod hostname;
mod identity_certificate_expiry;
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
            v.push(Box::new(
                identity_certificate_expiry::IdentityCertificateExpiry::default(),
            ));
            v.push(Box::new(certs_preloaded::CertsPreloaded::default()));
            v
        }),
        ("Connectivity checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.extend(daemons_running::daemons_running());
            v.push(Box::new(
                host_connect_dps_endpoint::HostConnectDpsEndpoint::default(),
            ));
            v
        }),
    ]
}
