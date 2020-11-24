use std::path::PathBuf;

use structopt::StructOpt;

mod additional_info;
mod checks;

pub use additional_info::AdditionalInfo;
pub use checks::all_checks;

const DEFAULT_BIN_DIR: &str = "/usr/bin/";
const DEFAULT_CFG_DIR: &str = "/etc/aziot/";

#[derive(StructOpt)]
pub struct CheckerCfg {
    // TODO: add aziot version info to https://github.com/Azure/azure-iotedge
    // /// Sets the expected version of the iotedged binary. Defaults to the value
    // /// contained in <http://aka.ms/latest-iotedge-stable>
    // expected_iotedged_version: String,
    //
    /// Sets the path to the aziotd configurations directory.
    ///
    /// Only available in debug mode for local testing.
    #[cfg(debug_assertions)]
    #[structopt(
        long,
        value_name = "DEFAULT_CFG_DIR",
        default_value = DEFAULT_CFG_DIR
    )]
    pub cfg_path: PathBuf,

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
}

/// The various ways a check can resolve.
///
/// Check functions return `Result<CheckResult, failure::Error>` where `Err` represents the check failed.
#[derive(Debug)]
pub enum CheckResult {
    /// Check succeeded.
    Ok,

    /// Check failed with a warning.
    Warning(crate::Error),

    /// Check is not applicable and was ignored. Should be treated as success.
    Ignored,

    /// Check was skipped because of errors from some previous checks. Should be treated as an error.
    Skipped,

    /// Check failed, and further checks should be performed.
    Failed(crate::Error),

    /// Check failed, and further checks should not be performed.
    Fatal(crate::Error),
}

pub struct CheckerMeta {
    /// Unique human-readable identifier for the check.
    pub id: &'static str,
    /// A brief description of what this check does.
    pub description: &'static str,
}

/// Container for any cached data shared between different checks.
pub struct CheckerCache {}

#[async_trait::async_trait]
pub trait Checker: erased_serde::Serialize {
    fn meta(&self) -> CheckerMeta;

    async fn execute(&mut self, cfg: &CheckerCfg, cache: &mut CheckerCache) -> CheckResult;
}

erased_serde::serialize_trait_object!(Checker);
