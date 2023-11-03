// Copyright (c) Microsoft. All rights reserved.

use std::process::Command;

use anyhow::{Context, Result};

use super::{print_command_error, ServiceDefinition};

pub fn stop(services: &[&ServiceDefinition]) -> Result<()> {
    // stop all services
    for service in services.iter().map(|s| s.service) {
        print!("Stopping {service}...");
        let result = Command::new("systemctl")
            .args(["stop", service])
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
