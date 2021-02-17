// Copyright (c) Microsoft. All rights reserved.

use std::fs;
use std::io::prelude::*;
use std::process::Command;

use anyhow::{Context, Result};

use crate::{program_name, ServiceDefinition};

pub fn set_log_level(services: &[&ServiceDefinition], level: log::Level) -> Result<()> {
    for service in services.iter().map(|s| s.service) {
        write_log_level_file(service, level).with_context(|| {
            format!("could not write log level service override for {}", service)
        })?;
    }
    Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .context("could not run systemctl daemon-reload")?;

    println!("Set log level to {} for all services. Run the `{} system restart` command for the changes to take effect.", level, program_name());
    Ok(())
}

fn write_log_level_file(service: &str, level: log::Level) -> Result<()> {
    let directory = format!("/etc/systemd/system/{}.d", service);
    fs::create_dir_all(&directory)?;

    let filename = format!("{}/log-level.conf", directory);
    let contents = format!("[Service]\nEnvironment=AZIOT_LOG={}", level);

    let mut file = fs::File::create(filename)?;
    file.write_all(contents.as_bytes())?;

    Ok(())
}
