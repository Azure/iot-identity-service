// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

const LOG_LEVEL_ENV_VAR: &str = "AZIOT_LOG";

pub fn try_init() -> Result<(), log::SetLoggerError> {
    env_logger::Builder::new()
        .format(|fmt, record| {
            use std::io::Write;

            let level = match record.level() {
                log::Level::Trace => "TRCE",
                log::Level::Debug => "DBUG",
                log::Level::Info => "INFO",
                log::Level::Warn => "WARN",
                log::Level::Error => "ERR!",
            };
            let timestamp = fmt.timestamp();

            if record.level() >= log::Level::Debug {
                writeln!(
                    fmt,
                    "<{}>{} [{}] - [{}] {}",
                    to_syslog_level(record.level()),
                    timestamp,
                    level,
                    record.target(),
                    record.args()
                )
            } else {
                writeln!(
                    fmt,
                    "<{}>{} [{}] - {}",
                    to_syslog_level(record.level()),
                    timestamp,
                    level,
                    record.args()
                )
            }
        })
        .filter_level(log::LevelFilter::Info)
        .parse_env(LOG_LEVEL_ENV_VAR)
        .try_init()
}

fn to_syslog_level(level: log::Level) -> i8 {
    match level {
        log::Level::Error => 3,
        log::Level::Warn => 4,
        log::Level::Info => 6,
        log::Level::Debug | log::Level::Trace => 7,
    }
}
