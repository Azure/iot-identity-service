use std::fmt;
use std::fs;
use std::io::prelude::*;
use std::process::Command;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::{program_name, ServiceDefinition};

#[allow(clippy::missing_errors_doc)]
pub fn set_log_level(services: &[&ServiceDefinition], level: LogLevel) -> Result<()> {
    for ServiceDefinition {
        service,
        sockets: _,
    } in services
    {
        write_log_level_file(service, level)?;
    }
    Command::new("systemctl").arg("daemon-reload").output()?;

    println!("Set log level to {} for all services. Run the `{} system restart` command for the changes to take effect.", level, program_name());
    Ok(())
}

fn write_log_level_file(service: &str, level: LogLevel) -> Result<()> {
    let directory = format!("/etc/systemd/system/{}.d", service);
    fs::create_dir_all("directory")?;

    let filename = format!("{}/log-level.conf", directory);
    let contents = format!(
        "[Service]
Environment=AZIOT_LOG={}",
        level
    );

    let mut file = fs::File::create(filename)
        .with_context(|| format!("Failed to create log-level.conf file for {}", service))?;
    file.write_all(contents.as_bytes())?;

    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Debug,
    Normal,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, &'static str> {
        Ok(match s {
            "normal" => LogLevel::Normal,
            "debug" => LogLevel::Debug,
            _ => return Err("invalid log level"),
        })
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Normal => write!(f, "warn"),
            LogLevel::Debug => write!(f, "debug"),
        }
    }
}
