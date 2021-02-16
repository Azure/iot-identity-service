use std::fmt;
use std::process::Command;

use anyhow::{Context, Result};

use crate::{program_name, ServiceDefinition};

#[allow(clippy::missing_errors_doc)]
pub fn get_status(processes: &[&ServiceDefinition]) -> Result<()> {
    let results: Vec<ServiceStatus<'_>> = processes
        .iter()
        .map(|process| -> Result<ServiceStatus<'_>> {
            Ok(ServiceStatus {
                service_name: process.service,
                service_status: read_status(process.service)?,
                sockets: process
                    .sockets
                    .iter()
                    .map(|socket| -> Result<SocketStatus<'_>> {
                        Ok(SocketStatus {
                            socket_name: socket,
                            socket_status: read_status(socket)?,
                        })
                    })
                    .collect::<Result<Vec<SocketStatus<'_>>>>()?,
            })
        })
        .collect::<Result<Vec<ServiceStatus<'_>>>>()?;

    if results.iter().any(|s| !s.ok()) {
        for result in &results {
            println!("{}: {}", result.service_name, result.service_status);
            for socket in &result.sockets {
                println!("{}: {}", socket.socket_name, socket.socket_status);
            }
            println!();
        }

        for result in results {
            if let Status::Failed(_) = result.service_status {
                print_logs(result.service_name, &result.service_status)?;
            }
            for socket in result.sockets {
                if !socket.ok() {
                    print_logs(socket.socket_name, &result.service_status)?;
                }
            }
        }

        let name = program_name();
        println!();
        println!();
        println!("Note: inactive services are considered OK, while inactive sockets are considered failed. This is because services will be inactive if not in use.");
        println!("For more detailed logs, use the `{} system logs` command. If the logs do not contain enough information, consider setting debug logs using `{} system set-log-level`.", name, name);
    } else {
        println!("Ok");
    }

    Ok(())
}

fn read_status(process: &str) -> Result<Status> {
    let result = Command::new("systemctl")
        .args(&["is-active", process])
        .output()
        .context("Failed to call systemctl is-active")?;

    let output = String::from_utf8_lossy(&result.stdout);

    let result = match output.trim() {
        "active" => Status::Active,
        "inactive" => Status::Inactive,
        _ => Status::Failed(format!(
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )),
    };

    Ok(result)
}

fn print_logs(process: &str, state: &Status) -> Result<()> {
    println!(
        "{} is in a bad state: {:?}. Printing the last 10 log lines.",
        process, state,
    );
    Command::new("journalctl")
        .args(&["-u", process, "--no-pager", "-e", "-n", "10"])
        .spawn()
        .context("Failed to spawn new process for printing logs")?
        .wait()
        .context("Failed to call journalctl")?;
    println!();

    Ok(())
}

#[derive(PartialEq, Debug)]
enum Status {
    Active,
    Failed(String),
    Inactive,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Active => write!(f, "active"),
            Status::Inactive => write!(f, "inactive"),
            Status::Failed(message) => write!(f, "{}", message),
        }
    }
}

#[derive(Debug)]
struct ServiceStatus<'a> {
    service_name: &'a str,
    service_status: Status,

    sockets: Vec<SocketStatus<'a>>,
}

impl<'a> ServiceStatus<'a> {
    fn ok(&self) -> bool {
        // If status is not failed and there are no sockets that are not ok
        !matches!(self.service_status, Status::Failed(_)) && !self.sockets.iter().any(|s| !s.ok())
    }
}

#[derive(Debug)]
struct SocketStatus<'a> {
    socket_name: &'a str,
    socket_status: Status,
}

impl<'a> SocketStatus<'a> {
    fn ok(&self) -> bool {
        self.socket_status == Status::Active
    }
}
