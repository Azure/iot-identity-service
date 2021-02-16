use std::ffi::OsString;

use anyhow::Result;
use structopt::StructOpt;

use aziotctl_common::{
    get_status, get_system_logs, restart, set_log_level, LogLevel, SERVICE_DEFINITIONS,
};

#[derive(StructOpt)]
pub enum SystemOptions {
    Restart(RestartOptions),
    Status(StatusOptions),
    Logs(LogsOptions),
    SetLogLevel(LogLevelOptions),
}

#[derive(StructOpt)]
#[structopt(about = "Restart the services")]
pub struct RestartOptions {}

#[derive(StructOpt)]
#[structopt(about = "Report the status of system")]
pub struct StatusOptions {}

#[derive(StructOpt)]
#[structopt(about = "Get logs for the services")]
pub struct LogsOptions {
    /// Extra args to be passed to journalctl
    #[structopt(last = true)]
    args: Vec<OsString>,
}

#[derive(StructOpt)]
#[structopt(about = "Set the log level of the services")]
pub struct LogLevelOptions {
    #[structopt(value_name = r#"One of "normal" or "debug"."#)]
    log_level: LogLevel,
}

pub fn system(options: SystemOptions) -> Result<()> {
    match options {
        SystemOptions::Restart(_) => restart(SERVICE_DEFINITIONS),
        SystemOptions::Status(_) => get_status(SERVICE_DEFINITIONS),
        SystemOptions::Logs(opts) => logs(&opts),
        SystemOptions::SetLogLevel(opts) => set_log_level(SERVICE_DEFINITIONS, opts.log_level),
    }
}

fn logs(options: &LogsOptions) -> Result<()>{
    let services: Vec<&str> = SERVICE_DEFINITIONS.iter().map(|s| s.service).collect();

    get_system_logs(&services, &options.args)
}
