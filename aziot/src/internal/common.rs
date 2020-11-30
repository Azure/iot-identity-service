use anyhow::{Context, Result};

pub fn get_hostname() -> Result<String> {
    if cfg!(test) {
        Ok("my-device".to_owned())
    } else {
        let mut hostname = vec![0_u8; 256];
        let hostname =
            nix::unistd::gethostname(&mut hostname).context("could not get machine hostname")?;
        let hostname = hostname
            .to_str()
            .context("could not get machine hostname")?;
        Ok(hostname.to_owned())
    }
}
