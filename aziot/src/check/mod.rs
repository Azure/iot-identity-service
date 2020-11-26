use std::collections::BTreeMap;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;

use colored::Colorize;
use serde::Serialize;
use structopt::StructOpt;

mod additional_info;
mod check_list_cli;
mod checks;

pub use check_list_cli::check_list;

use additional_info::AdditionalInfo;

const DEFAULT_CONFIG_DIR: &str = "/etc/aziot/";
const DEFAULT_BIN_DIR: &str = "/usr/bin/";

#[derive(StructOpt)]
#[structopt(about = "Check for common config and deployment issues")]
pub struct CheckCfg {
    /// Space-separated list of check IDs. The checks listed here will not be run.
    /// See 'aziot check-list' for details of all checks.
    #[structopt(
        long,
        value_name = "DONT_RUN",
        value_delimiter = " ",
        use_delimiter = true
    )]
    dont_run: Vec<String>,

    // TODO: add aziot version info to https://github.com/Azure/azure-iotedge
    // /// Sets the expected version of the iotedged binary. Defaults to the value
    // /// contained in <http://aka.ms/latest-iotedge-stable>
    // expected_iotedged_version: String,
    /// Sets the path to the aziotd daemon binaries.
    #[structopt(
        long,
        value_name = "PATH_TO_IOTEDGED",
        default_value = DEFAULT_BIN_DIR
    )]
    bin_path: PathBuf,

    /// Sets the hostname of the Azure IoT Hub that this device would connect to.
    /// If using manual provisioning, this does not need to be specified.
    #[structopt(long, value_name = "IOTHUB_HOSTNAME")]
    iothub_hostname: Option<PathBuf>,

    /// Sets the NTP server to use when checking host local time.
    #[structopt(long, value_name = "NTP_SERVER", default_value = "pool.ntp.org:123")]
    ntp_server: String,

    /// Output format. Note that JSON output contains some additional information
    /// like OS name, OS version, disk space, etc.
    #[structopt(short, long, value_name = "FORMAT", default_value = "text")]
    output: OutputFormat,

    /// Increases verbosity of output.
    #[structopt(short, long)]
    verbose: bool,

    /// Treats warnings as errors. Thus 'aziot check' will exit with non-zero
    /// code if it encounters warnings.
    #[structopt(long)]
    warnings_as_errors: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    JsonStream,
}

impl FromStr for OutputFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, &'static str> {
        Ok(match s {
            "text" => OutputFormat::Text,
            "json" => OutputFormat::Json,
            "json-stream" => OutputFormat::JsonStream,
            _ => return Err("invalid output format"),
        })
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
struct CheckerCache {}

#[async_trait::async_trait]
trait Checker: erased_serde::Serialize {
    fn meta(&self) -> CheckerMeta;

    async fn execute(&mut self, cfg: &CheckCfg, cache: &mut CheckerCache) -> CheckResult;
}

erased_serde::serialize_trait_object!(Checker);

pub async fn check(cfg: CheckCfg) -> Result<(), crate::Error> {
    let mut checks: BTreeMap<&str, CheckOutputSerializable> = Default::default();
    let mut check_data = checks::all_checks();
    let mut shared = CheckerCache {};

    let mut num_successful = 0_usize;
    let mut num_warnings = 0_usize;
    let mut num_skipped = 0_usize;
    let mut num_fatal = 0_usize;
    let mut num_errors = 0_usize;

    macro_rules! output {
        ($color:ident, $($args:tt)*) => {
            if matches!(cfg.output, OutputFormat::Text) {
                print!("{}", format!($($args)*).$color());
            }
        };
    }

    macro_rules! outputln {
        () => {
            if matches!(cfg.output, OutputFormat::Text) {
                println!();
            }
        };
        ($color:ident, $($args:tt)*) => {
            if matches!(cfg.output, OutputFormat::Text) {
                println!("{}", format!($($args)*).$color());
            }
        };
    }

    macro_rules! outputlns {
        ($color:ident, $first_line_indent:expr, $other_line_indent:expr, $lines:expr $(,)?) => {
            for (i, line) in $lines.enumerate() {
                outputln!(
                    $color,
                    "{}{}",
                    if i == 0 {
                        $first_line_indent
                    } else {
                        $other_line_indent
                    },
                    line
                );
            }
        };
    }

    for (section_name, section_checks) in &mut check_data {
        if num_fatal > 0 {
            break;
        }

        outputln!(normal, "{}", section_name);
        outputln!(normal, "{}", "-".repeat(section_name.len()));

        for check in section_checks {
            let check_name = check.meta().description;

            if num_fatal > 0 {
                break;
            }

            let check_result = if cfg.dont_run.iter().any(|s| s == check.meta().id) {
                CheckResult::Ignored
            } else {
                check.execute(&cfg, &mut shared).await
            };
            let additional_info =
                serde_json::to_value(&check).expect("serializing a check should never fail");

            let check_result_serializable = match check_result {
                CheckResult::Ok => {
                    num_successful += 1;
                    outputln!(green, "\u{221a} {} - OK", check_name);

                    CheckResultSerializable::Ok
                }
                CheckResult::Warning(ref warning) if !cfg.warnings_as_errors => {
                    num_warnings += 1;
                    outputln!(yellow, "\u{203c} {} - Warning", check_name);
                    outputlns!(yellow, "    ", "    ", warning.to_string().lines());
                    if cfg.verbose {
                        for cause in warning.iter_causes() {
                            outputlns!(
                                yellow,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Warning {
                        details: warning.iter_chain().map(ToString::to_string).collect(),
                    }
                }
                CheckResult::Ignored => CheckResultSerializable::Ignored,
                CheckResult::Skipped => {
                    num_skipped += 1;
                    if cfg.verbose {
                        outputln!(yellow, "\u{203c} {} - Warning", check_name);
                        outputln!(yellow, "    skipping because of previous failures");
                    }

                    CheckResultSerializable::Skipped
                }
                CheckResult::Fatal(err) => {
                    num_fatal += 1;
                    outputln!(red, "\u{00d7} {} - Error", check_name);
                    outputlns!(red, "    ", "    ", err.to_string().lines());
                    if cfg.verbose {
                        for cause in err.iter_causes() {
                            outputlns!(
                                red,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Fatal {
                        details: err.iter_chain().map(ToString::to_string).collect(),
                    }
                }
                CheckResult::Failed(err) | CheckResult::Warning(err) => {
                    num_errors += 1;
                    outputln!(red, "\u{00d7} {} - Error", check_name);
                    outputlns!(red, "    ", "    ", err.to_string().lines());
                    if cfg.verbose {
                        for cause in err.iter_causes() {
                            outputlns!(
                                red,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Error {
                        details: err.iter_chain().map(ToString::to_string).collect(),
                    }
                }
            };

            checks.insert(
                check.meta().id,
                CheckOutputSerializable {
                    result: check_result_serializable,
                    additional_info,
                },
            );
        }

        outputln!();
    }

    outputln!(green, "{} check(s) succeeded.", num_successful);

    if num_warnings > 0 {
        output!(yellow, "{} check(s) raised warnings.", num_warnings);
        if cfg.verbose {
            outputln!();
        } else {
            outputln!(yellow, " Re-run with --verbose for more details.");
        }
    }

    if num_fatal + num_errors > 0 {
        output!(red, "{} check(s) raised errors.", num_fatal + num_errors);
        if cfg.verbose {
            outputln!();
        } else {
            outputln!(red, " Re-run with --verbose for more details.");
        }
    }

    if num_skipped > 0 {
        output!(
            yellow,
            "{} check(s) were skipped due to errors from other checks.",
            num_skipped,
        );
        if cfg.verbose {
            outputln!();
        } else {
            outputln!(yellow, " Re-run with --verbose for more details.");
        }
    }

    let result = if num_fatal + num_errors > 0 {
        Err("".into())
    } else {
        Ok(())
    };

    if matches!(cfg.output, OutputFormat::Json) {
        let check_results = CheckResultsSerializable {
            additional_info: &AdditionalInfo::new(),
            checks,
        };

        if let Err(err) = serde_json::to_writer(std::io::stdout(), &check_results) {
            eprintln!("Could not write JSON output: {}", err,);
            return Err("".into());
        }

        println!();
    }

    result
}

#[derive(Debug, Serialize)]
struct CheckResultsSerializable<'a> {
    additional_info: &'a AdditionalInfo,
    checks: BTreeMap<&'static str, CheckOutputSerializable>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result")]
#[serde(rename_all = "snake_case")]
enum CheckResultSerializable {
    Ok,
    Warning { details: Vec<String> },
    Ignored,
    Skipped,
    Fatal { details: Vec<String> },
    Error { details: Vec<String> },
}

#[derive(Debug, Serialize)]
struct CheckOutputSerializable {
    result: CheckResultSerializable,
    additional_info: serde_json::Value,
}
