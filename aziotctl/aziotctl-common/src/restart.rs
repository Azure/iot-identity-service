use std::io::{self, Write};
use std::process::Command;

use crate::ServiceDefinition;

pub fn restart(services: &[&ServiceDefinition]) {
    // stop all services
    for ServiceDefinition {
        service,
        sockets: _,
    } in services
    {
        print!("Stopping {}...", service);
        let result = Command::new("systemctl")
            .args(&["stop", service])
            .output()
            .unwrap();

        if result.status.success() {
            println!("Stopped!");
        } else {
            println!("\nError stopping {}", service);
            io::stdout().write_all(&result.stdout).unwrap();
            io::stderr().write_all(&result.stderr).unwrap();
            println!();
        }
    }

    // start all sockets
    for ServiceDefinition {
        service: _,
        sockets,
    } in services
    {
        for socket in sockets.iter() {
            start(socket);
        }
    }

    // start the first service. This service should be the one that will use the other services
    start(services[0].service);
}

fn start(name: &str) {
    print!("Starting {}...", name);
    let result = Command::new("systemctl")
        .args(&["start", name])
        .output()
        .unwrap();

    if result.status.success() {
        println!("Started!");
    } else {
        println!("\nError starting {}", name);
        io::stdout().write_all(&result.stdout).unwrap();
        io::stderr().write_all(&result.stderr).unwrap();
        println!();
    }
}
