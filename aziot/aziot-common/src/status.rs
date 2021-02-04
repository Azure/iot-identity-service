use std::process::Command;

use crate::ServiceDefinition;

#[derive(PartialEq)]
enum Status {
    Active,
    Failed,
    Inactive,
}

#[allow(clippy::module_name_repetitions)]
pub fn get_status(processes: &[&ServiceDefinition]) {
    for process in processes {
        print!("Checking {}...", process.service);
        if let Status::Failed = read_status(process.service) {
            print_logs(process.service);
        } else {
            println!("Success!");
        }

        for socket in process.sockets {
            print!("Checking {}...", socket);
            match read_status(socket) {
                Status::Failed | Status::Inactive => {
                    print_logs(socket);
                }
                Status::Active => println!("Success!"),
            }
        }
        println!();
    }
}

fn read_status(process: &str) -> Status {
    let result = Command::new("systemctl")
        .args(&["is-active", process])
        .output()
        .unwrap();

    let output: &str = &"active".to_string();

    match output {
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
    println!("Failed! Printing the last 10 log lines.");
    Command::new("journalctl")
        .args(&["-u", process, "--no-pager", "-e", "-n", "10"])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    println!();
}
