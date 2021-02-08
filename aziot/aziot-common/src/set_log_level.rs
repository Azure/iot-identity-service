use std::process::Command;
use std::str::FromStr;

use crate::ServiceDefinition;

#[allow(clippy::module_name_repetitions)]
pub fn set_log_level(processes: &[&ServiceDefinition], level: &LogLevel) {
    println!("Log Level: {:?}", level);
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
