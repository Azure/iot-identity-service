// Copyright (c) Microsoft. All rights reserved.

use serde::Serialize;
use structopt::StructOpt;

mod additional_info;
mod checks;
mod util;

pub(crate) use additional_info::AdditionalInfo;
pub(crate) use checks::all_checks;

// NOTE: this struct gets `structopt(flatten)`ed as part of the `aziot check` subcommand.
#[derive(StructOpt)]
pub struct CheckerCfg {
    // TODO: add aziot version info to https://github.com/Azure/azure-iotedge
    // /// Sets the expected version of the iotedged binary. Defaults to the value
    // /// contained in <http://aka.ms/latest-iotedge-stable>
    // expected_iotedged_version: String,
    //
    /// Sets the NTP server to use when checking host local time.
    #[structopt(long, value_name = "NTP_SERVER", default_value = "pool.ntp.org:123")]
    pub ntp_server: String,

    // (Manually populated to match top-level CheckOptions value)
    #[structopt(skip)]
    pub verbose: bool,

    /// Sets the hostname of the Azure IoT Hub that this device would connect to.
    /// If using manual provisioning, this does not need to be specified.
    #[structopt(long, value_name = "IOTHUB_HOSTNAME")]
    pub iothub_hostname: Option<String>,
}

pub struct CheckerShared {
    cfg: CheckerCfg,
}

impl CheckerShared {
    pub fn new(cfg: CheckerCfg) -> CheckerShared {
        CheckerShared { cfg }
    }
}

/// The various ways a check can resolve.
///
/// Check functions return `Result<CheckResult, failure::Error>` where `Err` represents the check failed.
#[derive(Debug)]
pub enum CheckResult {
    /// Check succeeded.
    Ok,

    /// Check failed with a warning.
    Warning(anyhow::Error),

    /// Check is not applicable and was ignored. Should be treated as success.
    Ignored,

    /// Check was skipped because of errors from some previous checks. Should be treated as an error.
    Skipped,

    /// Check failed, and further checks should be performed.
    Failed(anyhow::Error),

    /// Check failed, and further checks should not be performed.
    Fatal(anyhow::Error),
}

#[derive(Debug, Copy, Clone, Serialize)]
pub struct CheckerMeta {
    /// Unique human-readable identifier for the check.
    pub id: &'static str,
    /// A brief description of what this check does.
    pub description: &'static str,
}

impl From<CheckerMeta> for aziot_check_common::CheckerMetaSerializable {
    fn from(meta: CheckerMeta) -> aziot_check_common::CheckerMetaSerializable {
        aziot_check_common::CheckerMetaSerializable {
            id: meta.id.into(),
            description: meta.description.into(),
        }
    }
}

#[async_trait::async_trait]
pub trait Checker: erased_serde::Serialize {
    fn meta(&self) -> CheckerMeta;

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult;
}

erased_serde::serialize_trait_object!(Checker);

/// Container for any cached data shared between different checks.
pub struct CheckerCache {
    pub cfg: DaemonConfigs,
}

impl CheckerCache {
    pub fn new() -> CheckerCache {
        CheckerCache {
            cfg: DaemonConfigs::default(),
        }
    }
}

// populated during the `well_formed_configs` checks
#[derive(Default)]
pub struct DaemonConfigs {
    pub certd: Option<aziot_certd_config::Config>,
    pub keyd: Option<aziot_keyd_config::Config>,
    pub tpmd: Option<aziot_tpmd_config::Config>,
    pub identityd: Option<aziot_identityd_config::Settings>,
    pub identityd_prev: Option<aziot_identityd_config::Settings>,
}
