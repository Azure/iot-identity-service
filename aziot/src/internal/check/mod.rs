use std::path::PathBuf;

use structopt::StructOpt;

mod additional_info;
mod checks;

pub use additional_info::AdditionalInfo;
pub use checks::all_checks;

const DEFAULT_BIN_DIR: &str = "/usr/bin/";

// NOTE: this struct gets `structopt(flatten)`ed as part of the `aziot check` subcommand.
#[derive(StructOpt)]
pub struct CheckerCfg {
    // TODO: add aziot version info to https://github.com/Azure/azure-iotedge
    // /// Sets the expected version of the iotedged binary. Defaults to the value
    // /// contained in <http://aka.ms/latest-iotedge-stable>
    // expected_iotedged_version: String,
    //
    /// Sets the path to the aziotd daemon binaries directory.
    #[structopt(
        long,
        value_name = "PATH_TO_AZIOTD_BINS",
        default_value = DEFAULT_BIN_DIR
    )]
    pub bin_path: PathBuf,

    /// Sets the hostname of the Azure IoT Hub that this device would connect to.
    /// If using manual provisioning, this does not need to be specified.
    #[structopt(long, value_name = "IOTHUB_HOSTNAME")]
    pub iothub_hostname: Option<PathBuf>,

    /// Sets the NTP server to use when checking host local time.
    #[structopt(long, value_name = "NTP_SERVER", default_value = "pool.ntp.org:123")]
    pub ntp_server: String,

    // (Manually populated to match top-level CheckCfg value)
    #[structopt(skip)]
    pub verbose: bool,
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

pub struct CheckerMeta {
    /// Unique human-readable identifier for the check.
    pub id: &'static str,
    /// A brief description of what this check does.
    pub description: &'static str,
}

#[async_trait::async_trait]
pub trait Checker: erased_serde::Serialize {
    fn meta(&self) -> CheckerMeta;

    async fn execute(&mut self, checker_cfg: &CheckerCfg, cache: &mut CheckerCache) -> CheckResult;
}

erased_serde::serialize_trait_object!(Checker);

/// Container for any cached data shared between different checks.
pub struct CheckerCache {
    cfg: DaemonConfigsWrapper,
}

impl CheckerCache {
    pub fn new() -> CheckerCache {
        CheckerCache {
            cfg: DaemonConfigsWrapper::Loading(Default::default()),
        }
    }
}

pub enum DaemonConfigsWrapper {
    Loading(DaemonConfigsLoading),
    Loaded(DaemonConfigs),
}

pub struct DaemonConfigs {
    certd: aziot_certd::Config,
    keyd: aziot_keyd::Config,
    tpmd: aziot_tpmd::Config,
    identityd: aziot_identityd::settings::Settings,
}

#[derive(Default)]
pub struct DaemonConfigsLoading {
    certd: Option<aziot_certd::Config>,
    keyd: Option<aziot_keyd::Config>,
    tpmd: Option<aziot_tpmd::Config>,
    identityd: Option<aziot_identityd::settings::Settings>,
}

impl DaemonConfigsLoading {
    fn try_into_loaded(&mut self) -> Option<DaemonConfigs> {
        match (
            self.certd.as_ref(),
            self.keyd.as_ref(),
            self.tpmd.as_ref(),
            self.identityd.as_ref(),
        ) {
            (Some(_), Some(_), Some(_), Some(_)) => Some(DaemonConfigs {
                certd: self.certd.take().unwrap(),
                keyd: self.keyd.take().unwrap(),
                tpmd: self.tpmd.take().unwrap(),
                identityd: self.identityd.take().unwrap(),
            }),
            _ => None,
        }
    }
}

impl DaemonConfigsWrapper {
    pub fn unwrap_loading(&mut self) -> &mut DaemonConfigsLoading {
        match self {
            DaemonConfigsWrapper::Loading(ref mut incomplete) => incomplete,
            _ => panic!("daemon configs have already been loaded!"),
        }
    }

    pub fn unwrap(&mut self) -> &mut DaemonConfigs {
        match self {
            DaemonConfigsWrapper::Loaded(ref mut loaded) => loaded,
            DaemonConfigsWrapper::Loading(loading) => match loading.try_into_loaded() {
                Some(loaded) => {
                    *self = DaemonConfigsWrapper::Loaded(loaded);
                    self.unwrap()
                }
                None => panic!("daemon configs haven't been loaded yet!"),
            },
        }
    }
}
