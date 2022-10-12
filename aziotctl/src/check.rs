// Copyright (c) Microsoft. All rights reserved.

use std::collections::BTreeMap;
use std::io::prelude::*;

use anyhow::Result;
use colored::Colorize;

use aziotctl_common::{
    CheckOutputSerializable, CheckOutputSerializableStreaming, CheckResultSerializable,
    CheckResultsSerializable,
};

use crate::internal::check::{
    AdditionalInfo, CheckResult, CheckerCache, CheckerCfg, CheckerShared,
};

#[derive(clap::Args)]
#[command(about = "Check for common config and deployment issues")]
pub struct Options {
    /// Space-separated list of check IDs. The checks listed here will not be run.
    /// See 'aziotctl check-list' for details of all checks.
    #[arg(
        long,
        value_name = "DONT_RUN",
        value_delimiter = ' ',
    )]
    dont_run: Vec<String>,

    /// Output format. One of "text" or "json". Note that JSON output contains
    /// some additional information like OS name, OS version, disk space, etc.
    #[arg(short, long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Treats warnings as errors. Thus 'aziotctl check' will exit with non-zero
    /// code if it encounters warnings.
    #[arg(long)]
    warnings_as_errors: bool,

    #[command(flatten)]
    checker_cfg: CheckerCfg,
}

#[derive(Clone, Copy, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    Text,
    Json,
    JsonStream,
}

pub async fn check(cfg: Options) -> Result<()> {
    let verbose = cfg.checker_cfg.verbose;
    let checker_shared = CheckerShared::new(cfg.checker_cfg);

    let mut checks: BTreeMap<String, CheckOutputSerializable> = Default::default();
    let mut check_data = crate::internal::check::all_checks();
    let mut check_cache = CheckerCache::new();

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

    'all_checks: for (section_name, section_checks) in &mut check_data {
        outputln!(normal, "{}", section_name);
        outputln!(
            normal,
            "{:->section_name_len$}",
            "",
            section_name_len = section_name.len()
        );

        if matches!(cfg.output, OutputFormat::JsonStream) {
            serde_json::to_writer(
                std::io::stdout(),
                &CheckOutputSerializableStreaming::Section {
                    name: (*section_name).into(),
                },
            )?;
            std::io::stdout().flush()?;
        }

        for check in section_checks {
            let check_result = if cfg.dont_run.iter().any(|s| s == check.meta().id) {
                CheckResult::Ignored
            } else {
                check.execute(&checker_shared, &mut check_cache).await
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
                    if verbose {
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
                    if verbose {
                        outputln!(yellow, "\u{203c} {} - Warning", check_name);
                        outputln!(yellow, "    skipping because of previous failures");
                    }

                    CheckResultSerializable::Skipped
                }
                CheckResult::Fatal(err) => {
                    num_fatal += 1;
                    outputln!(red, "\u{00d7} {} - Error", check_name);
                    outputlns!(red, "    ", "    ", err.to_string().lines());
                    if verbose {
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
                    if verbose {
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
                    checks.insert(check.meta().id.into(), output_serializable);
                }
                OutputFormat::JsonStream => {
                    serde_json::to_writer(
                        std::io::stdout(),
                        &CheckOutputSerializableStreaming::Check {
                            meta: check.meta().into(),
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
        if verbose {
            outputln!();
        } else {
            outputln!(yellow, " Re-run with --verbose for more details.");
        }
    }

    if num_fatal + num_errors > 0 {
        output!(red, "{} check(s) raised errors.", num_fatal + num_errors);
        if verbose {
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
        if verbose {
            outputln!();
        } else {
            outputln!(yellow, " Re-run with --verbose for more details.");
        }
    }

    let top_level_additional_info = {
        let (iothub_hostname, local_gateway_hostname) = match check_cache.cfg.identityd {
            Some(s) => {
                use aziot_identityd_config::ProvisioningType;
                let iothub_hostname = match s.provisioning.provisioning {
                    ProvisioningType::Manual {
                        iothub_hostname, ..
                    } => Some(iothub_hostname),
                    _ => None,
                };
                (iothub_hostname, s.provisioning.local_gateway_hostname)
            }
            None => (None, None),
        };

        serde_json::to_value(&AdditionalInfo::new(
            iothub_hostname,
            local_gateway_hostname,
        ))?
    };

    match cfg.output {
        OutputFormat::JsonStream => {
            serde_json::to_writer(
                std::io::stdout(),
                &CheckOutputSerializableStreaming::AdditionalInfo(top_level_additional_info),
            )?;
            std::io::stdout().flush()?;
        }
        OutputFormat::Json => {
            let check_results = CheckResultsSerializable {
                additional_info: top_level_additional_info,
                checks,
            };

            if let Err(err) = serde_json::to_writer(std::io::stdout(), &check_results) {
                eprintln!("Could not write JSON output: {}", err);
            }
        }
        OutputFormat::Text => {}
    }

    println!();

    Ok(())
}
