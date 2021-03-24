// Copyright (c) Microsoft. All rights reserved.

use std::io::{self, Write};
use std::process::Command;

use anyhow::{Context, Result};

use crate::ServiceDefinition;

pub fn stop(services: &[&ServiceDefinition]) -> Result<()> {
    // stop all services
    for service in services.iter().map(|s| s.service) {
        print!("Stopping {}...", service);
        let result = Command::new("systemctl")
            .args(&["stop", service])
            .output()
            .context("Failed to call systemctl stop")?;

        if result.status.success() {
            println!("Stopped!");
        } else {
            print_command_error(&result);
        }
    }

    Ok(())
}

fn print_command_error(result: &std::process::Output) {
    eprintln!("systemctl exited with non-zero status code.");
    eprintln!("stdout:");
    eprintln!("=======");
    io::stdout().write_all(&result.stdout).unwrap();
    eprintln!("stderr:");
    eprintln!("=======");
    io::stdout().write_all(&result.stderr).unwrap();
    eprintln!();
}
