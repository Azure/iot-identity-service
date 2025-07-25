// Copyright (c) Microsoft. All rights reserved.

use std::collections::BTreeMap;

use serde::Serialize;

mod additional_info;
mod checks;
mod util;

pub(crate) use additional_info::AdditionalInfo;
pub(crate) use checks::all_checks;

// NOTE: This struct gets `structopt(flatten)`ed as part of the `aziotctl check` subcommand.
#[derive(clap::Args)]
pub struct CheckerCfg {
    /// Sets the NTP server to use when checking host local time.
    #[arg(long, value_name = "NTP_SERVER", default_value = "pool.ntp.org:123")]
    pub ntp_server: String,

    /// Increases verbosity of output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Sets the hostname of the Hub that this device would connect to.
    /// If using manual provisioning, this does not need to be specified.
    #[arg(long, value_name = "IOTHUB_HOSTNAME")]
    pub iothub_hostname: Option<String>,

    /// Sets the proxy URI that this device would use to connect to Azure DPS and Hub endpoints.
    #[arg(long, value_name = "PROXY_URI")]
    pub proxy_uri: Option<hyper::Uri>,

    /// If set, the check compares the installed package version to this string.
    /// Otherwise, the version is fetched from <http://aka.ms/azure-iotedge-latest-versions>
    #[arg(long, value_name = "VERSION")]
    pub expected_aziot_version: Option<String>,
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

#[derive(Copy, Clone, Debug, Serialize)]
pub struct CheckerMeta {
    /// Unique human-readable identifier for the check.
    pub id: &'static str,
    /// A brief description of what this check does.
    pub description: &'static str,
}

impl From<CheckerMeta> for aziotctl_common::CheckerMetaSerializable {
    fn from(meta: CheckerMeta) -> aziotctl_common::CheckerMetaSerializable {
        aziotctl_common::CheckerMetaSerializable {
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
#[derive(Default)]
pub struct CheckerCache {
    pub cfg: DaemonConfigs,
    daemons_running: DaemonsRunning,
    certs: BTreeMap<String, openssl::x509::X509>,
    private_keys: BTreeMap<String, openssl::pkey::PKey<openssl::pkey::Private>>,
}

impl CheckerCache {
    pub fn new() -> CheckerCache {
        Default::default()
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

#[derive(Default)]
struct DaemonsRunning {
    certd: bool,
    identityd: bool,
    keyd: bool,
    tpmd: bool,
}
