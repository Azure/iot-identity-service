use std::fmt;
use std::process::Command;

use crate::ServiceDefinition;

#[allow(clippy::module_name_repetitions)]
pub fn get_status(processes: &[&ServiceDefinition]) {
    let results: Vec<ServiceStatus<'_>> = processes
        .iter()
        .map(|process| ServiceStatus {
            service_name: process.service,
            service_status: read_status(process.service),
            sockets: process
                .sockets
                .iter()
                .map(|socket| SocketStatus {
                    socket_name: socket,
                    socket_status: read_status(socket),
                })
                .collect(),
        })
        .collect();

    if results.iter().any(|s| !s.ok()) {
        for result in &results {
            println!("{}: {}", result.service_name, result.service_status);
            for socket in &result.sockets {
                println!("{}: {}", socket.socket_name, socket.socket_status);
            }
            println!();
        }

        for result in &results {
            if result.service_status == Status::Failed {
                print_logs(result.service_name);
            }
            for socket in &result.sockets {
                if !socket.ok() {
                    print_logs(socket.socket_name);
                }
            }
        }
    } else {
        println!("Ok");
    }
}

fn read_status(process: &str) -> Status {
    let result = Command::new("systemctl")
        .args(&["is-active", process])
        .output()
        .unwrap();

    let output = String::from_utf8_lossy(&result.stdout);

    match output.trim() {
        "active" => Status::Active,
        "failed" => Status::Failed,
        "inactive" => Status::Inactive,
        &_ => {
            println!("\nError calling `systemctl is-active {}`.", process);
            println!(
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            println!("Treating status as failed.");
            Status::Failed
        }
    }
}

fn print_logs(process: &str) {
    println!("{} is in a bad state. Printing the last 10 log lines.", process);
    Command::new("journalctl")
        .args(&["-u", process, "--no-pager", "-e", "-n", "10"])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    println!();
}

#[derive(PartialEq)]
enum Status {
    Active,
    Failed,
    Inactive,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Active => write!(f, "active"),
            Status::Inactive => write!(f, "inactive"),
            Status::Failed => write!(f, "failed"),
        }
    }
}

struct ServiceStatus<'a> {
    service_name: &'a str,
    service_status: Status,

    sockets: Vec<SocketStatus<'a>>,
}

impl<'a> ServiceStatus<'a> {
    fn ok(&self) -> bool {
        self.service_status != Status::Failed && !self.sockets.iter().any(|s| !s.ok())
    }
}

struct SocketStatus<'a> {
    socket_name: &'a str,
    socket_status: Status,
}

impl<'a> SocketStatus<'a> {
    fn ok(&self) -> bool {
        self.socket_status == Status::Active
    }
}
