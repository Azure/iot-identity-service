use std::collections::BTreeMap;
use std::io::prelude::*;
use std::str::FromStr;

use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use structopt::StructOpt;

use crate::internal::check::{AdditionalInfo, CheckResult, CheckerCache, CheckerCfg};

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

    #[structopt(flatten)]
    checker_cfg: CheckerCfg,
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

pub async fn check(mut cfg: CheckCfg) -> Result<()> {
    // manually pass verbosity down to the checker-specific configuration
    cfg.checker_cfg.verbose = cfg.verbose;
    let cfg = cfg; // set cfg as immutable

    let mut checks: BTreeMap<&str, CheckOutputSerializable> = Default::default();
    let mut check_data = crate::internal::check::all_checks();
    let mut shared = CheckerCache::new();

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

    let top_level_additional_info = AdditionalInfo::new();

    if matches!(cfg.output, OutputFormat::JsonStream) {
        serde_json::to_writer(
            std::io::stdout(),
            &CheckResultsSerializableStreaming::AdditionalInfo(&top_level_additional_info),
        )?;
        std::io::stdout().flush()?;
    }

    'all_checks: for (section_name, section_checks) in &mut check_data {
        outputln!(normal, "{}", section_name);
        outputln!(normal, "{}", "-".repeat(section_name.len()));

        for check in section_checks {
            let check_result = if cfg.dont_run.iter().any(|s| s == check.meta().id) {
                CheckResult::Ignored
            } else {
                check.execute(&cfg.checker_cfg, &mut shared).await
            };
            let additional_info = serde_json::to_value(&check)?;

            let check_name = check.meta().description;
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
                        for cause in warning.chain().skip(1) {
                            outputlns!(
                                yellow,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Warning {
                        details: warning.chain().map(ToString::to_string).collect(),
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
                        for cause in err.chain().skip(1) {
                            outputlns!(
                                red,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Fatal {
                        details: err.chain().map(ToString::to_string).collect(),
                    }
                }
                CheckResult::Failed(err) | CheckResult::Warning(err) => {
                    num_errors += 1;
                    outputln!(red, "\u{00d7} {} - Error", check_name);
                    outputlns!(red, "    ", "    ", err.to_string().lines());
                    if cfg.verbose {
                        for cause in err.chain().skip(1) {
                            outputlns!(
                                red,
                                "        caused by: ",
                                "                   ",
                                cause.to_string().lines(),
                            );
                        }
                    }

                    CheckResultSerializable::Error {
                        details: err.chain().map(ToString::to_string).collect(),
                    }
                }
            };

            let output_serializable = CheckOutputSerializable {
                result: check_result_serializable,
                additional_info,
            };

            match cfg.output {
                OutputFormat::Text => {}
                OutputFormat::Json => {
                    checks.insert(check.meta().id, output_serializable);
                }
                OutputFormat::JsonStream => {
                    serde_json::to_writer(
                        std::io::stdout(),
                        &CheckResultsSerializableStreaming::Check {
                            id: check.meta().id,
                            output: output_serializable,
                        },
                    )?;
                    std::io::stdout().flush()?;
                }
            }

            if num_fatal > 0 {
                break 'all_checks;
            }
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

    if matches!(cfg.output, OutputFormat::Json) {
        let check_results = CheckResultsSerializable {
            additional_info: &top_level_additional_info,
            checks,
        };

        if let Err(err) = serde_json::to_writer(std::io::stdout(), &check_results) {
            eprintln!("Could not write JSON output: {}", err,);
        }

        println!();
    }

    Ok(())
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

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
enum CheckResultsSerializableStreaming<'a> {
    AdditionalInfo(&'a AdditionalInfo),
    Check {
        id: &'static str,
        #[serde(flatten)]
        output: CheckOutputSerializable,
    },
}
