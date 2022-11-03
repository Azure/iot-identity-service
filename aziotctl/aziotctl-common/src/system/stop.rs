// Copyright (c) Microsoft. All rights reserved.

use std::process::Command;

use anyhow::{Context, Result};

use super::{print_command_error, ServiceDefinition};

#[cfg(not(feature = "snapctl"))]
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

#[cfg(feature = "snapctl")]
pub fn stop(services: &[&ServiceDefinition]) -> Result<()> {
    let snap_instance_name = match std::env::var("SNAP_INSTANCE_NAME") {
        Ok(snap_instance_name) => snap_instance_name,
        Err(_) => {
            std::env::var("SNAP_NAME").expect("snapctl must be used within the context of a snap")
        }
    };

    print!("Stopping {} services...", snap_instance_name);

    let service_names = services
        .iter()
        .map(|s| format!("{}.{}", snap_instance_name, s.service));

    let result = Command::new("snapctl")
        .arg("stop")
        .args(service_names)
        .output()
        .context("Failed to call snapctl stop")?;

    if result.status.success() {
        println!("Stopped!");
    } else {
        print_command_error(&result);
    }

    Ok(())
}
