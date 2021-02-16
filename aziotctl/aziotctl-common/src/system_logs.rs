// Copyright (c) Microsoft. All rights reserved.

use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result};

pub fn get_system_logs(processes: &[&str], additional_args: &[OsString]) -> Result<()> {
    let processes = processes.iter().flat_map(|p| vec!["-u", p]);
    let default_args = ["-e".into(), "--no-pager".into()];

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
