use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::Command;
use std::str::FromStr;

use crate::ServiceDefinition;

#[allow(clippy::module_name_repetitions)]
/// # Errors
///
/// Will return `Err` if the systemd folder for the service does not exist or the user does not have
/// permission to read it.
pub fn set_log_level(services: &[&ServiceDefinition], level: LogLevel) -> Result<(), io::Error> {
    for ServiceDefinition {
        service,
        sockets: _,
    } in services
    {
        write_log(service, level)?;
    }
    Command::new("systemctl").arg("daemon-reload").output()?;

    println!("Set log level to {} for all services. Run the `system restart` command for the changes to take effect.", level);
    Ok(())
}

fn write_log(service: &str, level: LogLevel) -> Result<(), io::Error> {
    let filename = format!("/etc/systemd/system/{}.d/log-level.conf", service);
    let contents = format!(
        "[Service]
Environment=AZIOT_LOG={}",
        level
    );

    let mut file = File::create(filename)?;
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
