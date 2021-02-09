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
    args: Vec<String>,
}

#[derive(StructOpt)]
#[structopt(about = "Set the log level")]
pub struct LogLevelOptions {
    #[structopt(value_name = "normal | debug")]
    log_level: LogLevel,
}

pub fn system(options: SystemOptions) -> Result<()> {
    match options {
        SystemOptions::Restart(_) => {
            restart(SERVICE_DEFINITIONS);
            Ok(())
        }
        SystemOptions::Status(_) => {
            get_status(SERVICE_DEFINITIONS);
            Ok(())
        }
        SystemOptions::Logs(opts) => {
            logs(&opts);
            Ok(())
        }
        SystemOptions::SetLogLevel(opts) => Ok(set_log_level(SERVICE_DEFINITIONS, opts.log_level)?),
    }
}

fn logs(options: &LogsOptions) {
    let services: Vec<&str> = SERVICE_DEFINITIONS.iter().map(|s| s.service).collect();
    let args: Vec<&str> = options.args.iter().map(|a| &**a).collect();

    get_system_logs(&services, &args);
}