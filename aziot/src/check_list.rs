// Copyright (c) Microsoft. All rights reserved.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use structopt::StructOpt;

#[derive(StructOpt, Copy, Clone)]
#[structopt(about = "List the checks that are run for 'aziot check'")]
pub struct CheckListCfg {
    /// Output available checks as a JSON object.
    #[structopt(short, long)]
    json: bool,
}

pub fn check_list(cfg: CheckListCfg) -> Result<()> {
    let checks = crate::internal::check::all_checks();

    if cfg.json {
        let mut output: BTreeMap<String, Vec<_>> = BTreeMap::new();
        for (section_name, section_checks) in checks {
            output.insert(
                section_name.to_string(),
                section_checks.into_iter().map(|c| c.meta()).collect(),
            );
        }

        serde_json::to_writer(std::io::stdout(), &output).context("could not output to stdout")?;
    } else {
        // All our text is ASCII, so we can measure text width in bytes rather than
        // using unicode-segmentation to count graphemes.
        let widest_section_name_len = checks
            .iter()
            .map(|(section_name, _)| section_name.len())
            .max()
            .expect("Have at least one section");

        let section_name_column_width = widest_section_name_len + 1;
        let widest_check_id_len = checks
            .iter()
            .flat_map(|(_, section_checks)| section_checks)
            .map(|check| check.meta().id.len())
            .max()
            .expect("Have at least one check");
        let check_id_column_width = widest_check_id_len + 1;

        println!(
            "{:section_name_column_width$}{:check_id_column_width$}DESCRIPTION",
            "CATEGORY",
            "ID",
            section_name_column_width = section_name_column_width,
            check_id_column_width = check_id_column_width,
        );
        println!();

        for (section_name, section_checks) in &checks {
            for check in section_checks {
                println!(
                    "{:section_name_column_width$}{:check_id_column_width$}{}",
                    section_name,
                    check.meta().id,
                    check.meta().description,
                    section_name_column_width = section_name_column_width,
                    check_id_column_width = check_id_column_width,
                );
            }

            println!();
        }
    }

    Ok(())
}
