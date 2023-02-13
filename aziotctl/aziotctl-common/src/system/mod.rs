// Copyright (c) Microsoft. All rights reserved.

mod restart;
mod set_log_level;
mod status;
mod stop;
mod system_logs;

pub use restart::restart;
pub use set_log_level::set_log_level;
pub use status::get_status;
pub use stop::stop;
pub use system_logs::get_system_logs;

pub struct ServiceDefinition {
    pub service: &'static str,
    pub sockets: &'static [&'static str],
}

// Note, the ordering is important, since the first service is considered the root and will be started by the restart command.
#[cfg(not(feature = "snapctl"))]
pub const SERVICE_DEFINITIONS: &[&ServiceDefinition] = &[
    &ServiceDefinition {
        service: "aziot-identityd.service",
        sockets: &["aziot-identityd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-keyd.service",
        sockets: &["aziot-keyd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-certd.service",
        sockets: &["aziot-certd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-tpmd.service",
        sockets: &["aziot-tpmd.socket"],
    },
];

// Ordering is not important here, we defer it to snapd
#[cfg(feature = "snapctl")]
pub const SERVICE_DEFINITIONS: &[&ServiceDefinition] = &[
    &ServiceDefinition {
        service: "snap.azure-iot-identity.identityd.service",
        sockets: &["aziot-identityd.socket"],
    },
    &ServiceDefinition {
        service: "snap.azure-iot-identity.keyd.service",
        sockets: &["aziot-keyd.socket"],
    },
    &ServiceDefinition {
        service: "snap.azure-iot-identity.certd.service",
        sockets: &["aziot-certd.socket"],
    },
    &ServiceDefinition {
        service: "snap.azure-iot-identity.tpmd.service",
        sockets: &["aziot-tpmd.socket"],
    },
];

#[cfg(not(feature = "snapctl"))]
fn print_command_error(result: &std::process::Output) {
    use std::io::{self, Write};

    eprintln!("systemctl exited with non-zero status code.");
    eprintln!("stdout:");
    eprintln!("=======");
    io::stdout().write_all(&result.stdout).unwrap();
    eprintln!("stderr:");
    eprintln!("=======");
    io::stdout().write_all(&result.stderr).unwrap();
    eprintln!();
}

#[cfg(feature = "snapctl")]
fn print_command_error(result: &std::process::Output) {
    use std::io::{self, Write};

    eprintln!("snapctl exited with non-zero status code.");
    eprintln!("stdout:");
    eprintln!("=======");
    io::stdout().write_all(&result.stdout).unwrap();
    eprintln!("stderr:");
    eprintln!("=======");
    io::stdout().write_all(&result.stderr).unwrap();
    eprintln!();
}
