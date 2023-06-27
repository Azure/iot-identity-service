// Copyright (c) Microsoft. All rights reserved.

use std::ffi::OsStr;
use std::process::Command;

use anyhow::{Context, Result};

pub fn get_system_logs(processes: &[&str], additional_args: &[&OsStr]) -> Result<()> {
    let processes = processes.iter().flat_map(|p| vec!["-u", p]);
    let default_args = [OsStr::new("-e"), OsStr::new("--no-pager")];

    // NOTE: Clippy is incorrectly suggesting to remove the borrow on
    // default_args.
    #[allow(clippy::needless_borrow)]
    Command::new("journalctl")
        .args(processes)
        .args(if additional_args.is_empty() {
            &default_args
        } else {
            additional_args
        })
        .spawn()
        .context("Failed to spawn new process for getting logs")?
        .wait()
        .context("Failed to call journalctl")?;

    Ok(())
}
