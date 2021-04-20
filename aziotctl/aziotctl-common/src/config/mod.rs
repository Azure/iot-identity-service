// Copyright (c) Microsoft. All rights reserved.

use anyhow::Context;

pub mod apply;
pub mod super_config;

const AZIOT_KEYD_HOMEDIR_PATH: &str = "/var/lib/aziot/keyd";
const AZIOT_CERTD_HOMEDIR_PATH: &str = "/var/lib/aziot/certd";
const AZIOT_IDENTITYD_HOMEDIR_PATH: &str = "/var/lib/aziot/identityd";

/// The ID used for the device ID key (symmetric or X.509 private) and the device ID cert.
const DEVICE_ID_ID: &str = "device-id";

/// The ID used for the private key and cert that is used as the local CA.
const LOCAL_CA: &str = "local-ca";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server.
const EST_ID_ID: &str = "est-id";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server for the initial bootstrap.
const EST_BOOTSTRAP_ID: &str = "est-bootstrap-id";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server issuing device ID certs.
const DEVICE_ID_EST: &str = "device-id-est";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server issuing device ID certs for the initial bootstrap.
const DEVICE_ID_EST_BOOTSTRAP: &str = "device-id-est-bootstrap";

pub fn create_dir_all(
    path: &(impl AsRef<std::path::Path> + ?Sized),
    user: &nix::unistd::User,
    mode: u32,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = std::fs::create_dir_all(path)
        .with_context(|| format!("could not create {} directory", path_displayable))?;
    let () = nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {} directory", path_displayable))?;
    let () = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .with_context(|| {
            format!(
                "could not set permissions on {} directory",
                path_displayable
            )
        })?;

    Ok(())
}

pub fn write_file(
    path: &(impl AsRef<std::path::Path> + ?Sized),
    content: &[u8],
    user: &nix::unistd::User,
    mode: u32,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = std::fs::write(path, content)
        .with_context(|| format!("could not create {}", path_displayable))?;
    let () = nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {}", path_displayable))?;
    let () = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .with_context(|| format!("could not set permissions on {}", path_displayable))?;

    Ok(())
}

fn parse_manual_connection_string(
    connection_string: &str,
) -> Result<(String, String, Vec<u8>), String> {
    const HOSTNAME_KEY: &str = "HostName";
    const DEVICEID_KEY: &str = "DeviceId";
    const SHAREDACCESSKEY_KEY: &str = "SharedAccessKey";

    let mut iothub_hostname = None;
    let mut device_id = None;
    let mut symmetric_key = None;

    for sections in connection_string.split(';') {
        let mut parts = sections.split('=');
        match parts
            .next()
            .expect("str::split always returns at least one part")
        {
            HOSTNAME_KEY => iothub_hostname = parts.next(),
            DEVICEID_KEY => device_id = parts.next(),
            SHAREDACCESSKEY_KEY => symmetric_key = parts.next(),
            _ => (), // Ignore extraneous component in the connection string
        }
    }

    let iothub_hostname = iothub_hostname.ok_or(r#"required parameter "HostName" is missing"#)?;

    let device_id = device_id.ok_or(r#"required parameter "DeviceId" is missing"#)?;

    let symmetric_key =
        symmetric_key.ok_or(r#"required parameter "SharedAccessKey" is missing"#)?;
    let symmetric_key =
        base64::decode(symmetric_key)
        .map_err(|err| format!(r#"connection string's "SharedAccessKey" parameter could not be decoded from base64: {}"#, err))?;

    Ok((
        iothub_hostname.to_owned(),
        device_id.to_owned(),
        symmetric_key,
    ))
}
