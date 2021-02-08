use std::process::Command;

#[allow(clippy::module_name_repetitions)]
pub fn get_system_logs(processes: &[&str], mut additional_args: &[&str]) {
    let processes = processes.iter().flat_map(|p| vec!["-u", p]);
    if additional_args.is_empty() {
        additional_args = &["-e", "--no-pager"];
    }

    Command::new("journalctl")
        .args(processes)
        .args(additional_args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
