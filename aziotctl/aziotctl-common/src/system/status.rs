// Copyright (c) Microsoft. All rights reserved.

use std::fmt;
use std::process::Command;

use anyhow::{Context, Result};

use super::ServiceDefinition;

pub fn get_status(processes: &[&ServiceDefinition]) -> Result<()> {
    let services: Vec<ServiceStatus<'_>> = processes
        .iter()
        .map(|process| -> Result<ServiceStatus<'_>> {
            Ok(ServiceStatus {
                name: process.service,
                state: State::from_systemctl(process.service)?,
                sockets: process
                    .sockets
                    .iter()
                    .map(|socket| -> Result<SocketStatus<'_>> {
                        Ok(SocketStatus {
                            name: socket,
                            state: State::from_systemctl(socket)?,
                        })
                    })
                    .collect::<Result<Vec<SocketStatus<'_>>>>()?,
            })
        })
        .collect::<Result<Vec<ServiceStatus<'_>>>>()?;

    println!("System services:");
    for service in &services {
        println!(
            "    {:24}{}",
            format!(
                "{}:",
                service
                    .name
                    .strip_suffix(".service")
                    .unwrap_or(service.name)
            ),
            service.state()
        )
    }

    println!();

    for service in services {
        fn print_logs(process: &str, state: &State) -> Result<()> {
            println!("{}: {}: Printing the last 10 log lines.", process, state);
            Command::new("journalctl")
                .args(&["-u", process, "--no-pager", "-e", "-n", "10"])
                .spawn()
                .context("Failed to spawn new process for printing logs")?
                .wait()
                .context("Failed to call journalctl")?;
            println!();

            Ok(())
        }

        if !matches!(service.state(), State::Failed(_)) {
            continue;
        }

        println!(
            "{} is in a bad state because:",
            service
                .name
                .strip_suffix(".service")
                .unwrap_or(service.name)
        );

        print_logs(service.name, &service.state)?;
        for socket in service.sockets {
            if !matches!(socket.state, State::Active) {
                print_logs(socket.name, &socket.state)?;
            }
        }
    }

    let name = crate::program_name();
    println!("Use '{} system logs' to check for non-fatal errors.", name);
    println!(
        "Use '{} check' to diagnose connectivity and configuration issues.",
        name
    );

    Ok(())
}

#[derive(Clone, Debug)]
enum State {
    Active,
    Inactive,
    Failed(String),
}

impl State {
    fn from_systemctl(process: &str) -> Result<State> {
        let result = Command::new("systemctl")
            .args(&["is-active", process])
            .output()
            .context("Failed to call systemctl is-active")?;

        let output = String::from_utf8_lossy(&result.stdout);

        let result = match output.trim() {
            "active" => State::Active,
            "inactive" => State::Inactive,
            _ => State::Failed(format!(
                "{} {}",
                String::from_utf8_lossy(&result.stdout).trim(),
                String::from_utf8_lossy(&result.stderr).trim()
            )),
        };

        Ok(result)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Active => write!(f, "Running"),
            State::Inactive => write!(f, "Ready"),
            State::Failed(msg) => write!(f, "Down - {}", msg),
        }
    }
}

#[derive(Debug)]
struct ServiceStatus<'a> {
    name: &'a str,
    state: State,

    sockets: Vec<SocketStatus<'a>>,
}

impl<'a> ServiceStatus<'a> {
    fn state(&self) -> State {
        if matches!(self.state, State::Active)
            && !self
                .sockets
                .iter()
                .all(|socket| matches!(socket.state, State::Active))
        {
            return State::Failed("socket error".into());
        }

        self.state.clone()
    }
}

#[derive(Debug)]
struct SocketStatus<'a> {
    name: &'a str,
    state: State,
}
