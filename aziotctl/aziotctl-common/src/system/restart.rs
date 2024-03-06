// Copyright (c) Microsoft. All rights reserved.

use std::process::Command;

use anyhow::{Context, Result};

use super::{print_command_error, stop, ServiceDefinition};

#[cfg(not(feature = "snapctl"))]
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

#[cfg(not(feature = "snapctl"))]
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

#[cfg(feature = "snapctl")]
pub fn restart(services: &[&ServiceDefinition]) -> Result<()> {
    // stop all services
    stop(services)?;

    // start all services
    start(services)
}

#[cfg(feature = "snapctl")]
pub fn start(services: &[&ServiceDefinition]) -> Result<()> {
    let snap_instance_name = match std::env::var("SNAP_INSTANCE_NAME") {
        Ok(snap_instance_name) => snap_instance_name,
        Err(_) => {
            std::env::var("SNAP_NAME").expect("snapctl must be used within the context of a snap")
        }
    };

    print!("Starting {} services...", snap_instance_name);

    let service_names = services.iter().map(|s| {
        s.service
            .trim_start_matches("snap.")
            .trim_end_matches(".service")
    });

    let result = Command::new("snapctl")
        .arg("start")
        .args(service_names)
        .output()
        .context("Failed to call snapctl start")?;

    if result.status.success() {
        println!("Started!");
    } else {
        print_command_error(&result);
    }

    Ok(())
}
