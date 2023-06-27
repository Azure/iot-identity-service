// Copyright (c) Microsoft. All rights reserved.

use std::process::Command;

use anyhow::{Context, Result};

use super::{print_command_error, stop, ServiceDefinition};

pub fn restart(services: &[&ServiceDefinition]) -> Result<()> {
    // stop all services
    stop(services)?;

    // start all sockets
    for socket in services.iter().flat_map(|s| s.sockets) {
        start(socket)?;
    }

    // Start the first service. This is the primary service that should be enabled and started.
    // Other services will be started automatically by the primary service via socket activation as necessary.
    start(services[0].service)
}

fn start(name: &str) -> Result<()> {
    print!("Starting {}...", name);
    let result = Command::new("systemctl")
        .args(["start", name])
        .output()
        .context("Failed to call systemctl start")?;

    if result.status.success() {
        println!("Started!");
    } else {
        print_command_error(&result);
    }

    Ok(())
}
