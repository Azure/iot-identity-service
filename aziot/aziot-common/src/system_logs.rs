use std::process::Command;

#[allow(clippy::module_name_repetitions)]
pub fn get_system_logs(processes: &[&str], additional_args: &[&str]) {
    let processes = processes.iter().flat_map(|p| vec!["-u", p]);

    Command::new("journalctl")
        .args(processes)
        .args(additional_args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
