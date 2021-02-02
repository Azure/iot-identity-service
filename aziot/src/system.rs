use structopt::StructOpt;

use aziot_common::{restart, SERVICE_DEFINITIONS};

#[derive(StructOpt)]
pub enum SystemOptions {
    Restart(RestartOptions),
}

#[derive(StructOpt)]
#[structopt(about = "Restart the services")]
pub struct RestartOptions {
    /// Increases verbosity of output.
    #[structopt(short, long)]
    verbose: bool,
}

pub fn system(mut options: SystemOptions) {
    match options {
        SystemOptions::Restart(opts) => system_restart(opts),
    }
}

pub fn system_restart(mut cfg: RestartOptions) {
    println!("Test");
    // restart(SERVICE_DEFINITIONS)
}
