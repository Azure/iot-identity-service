fn main() {
    println!("cargo:rerun-if-changed=build.sh");

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let src = out_dir.join("src");
    let install = out_dir.join("install");
    assert!(
        std::process::Command::new("./build.sh")
            .arg(&src)
            .arg(&install)
            .arg("--disable-fapi")
            .arg("--disable-dependency-tracking")
            .arg("--disable-tcti-device")
            .arg("--disable-tcti-mssim")
            .arg("--disable-tcti-pcap")
            .arg("--disable-tcti-libtpms")
            .arg("--disable-tcti-cmd")
            .arg("--disable-weakcrypto")
            .status()
            .unwrap()
            .success()
    );
    println!("cargo:root={}", install.display());
}
