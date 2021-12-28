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

pub fn create_dir_all(
    path: &(impl AsRef<std::path::Path> + ?Sized),
    user: &nix::unistd::User,
    mode: u32,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = std::fs::create_dir_all(path)
        .with_context(|| format!("could not create {} directory", path_displayable))?;

    {
        // Enforce all parent directories of `path` are readable by `user`, by checking that at least one of these is true:
        //
        // - The directory is world-readable.
        // - The directory is group-readable and `user.gid` is the group.
        // - The directory is owner-readable and `user.uid` is the owner.
        //
        // Note that "readable" means r+x, not just r, because we're talking about directories.
        //
        // This is basically reimplementing `access(path, R_OK | X_OK)` but for the `user` user
        // instead of this process's user (which is root). The alternative would to spawn a child process
        // as `user` that does the `access` call. If we end up needing this pattern for more places
        // in the codebase, we can consider that option.
        //
        // If none of those conditions are true, we don't know which one is semantically correct to enforce,
        // so we default to enforcing the first one, ie we make the directory world-readable. `path` itself is still
        // created with the given `mode`, so it can be as open or closed as the caller wants it to be.

        let mut parent = path.parent();
        while let Some(dir) = parent {
            parent = dir.parent();

            let nix::sys::stat::FileStat {
                st_mode,
                st_uid,
                st_gid,
                ..
            } = nix::sys::stat::stat(dir)
                .with_context(|| format!("could not stat {} directory", dir.display()))?;
            if (st_mode & 0o005) != 0o005 {
                // World-readable
                continue;
            }
            if st_mode & 0o050 != 0o050 && st_gid == user.gid.as_raw() {
                // Group-readable by `user.gid`
                continue;
            }
            if st_mode & 0o500 != 0o500 && st_uid == user.uid.as_raw() {
                // Owner-readable by `user.uid`
                continue;
            }

            // Make it world-readable
            let () = std::fs::set_permissions(
                dir,
                std::os::unix::fs::PermissionsExt::from_mode(st_mode | 0o005),
            )
            .with_context(|| {
                format!("could not set permissions on {} directory", dir.display(),)
            })?;
        }
    }

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
        let parts = sections.split_once('=');
        match parts {
            Some((HOSTNAME_KEY, value)) => iothub_hostname = Some(value),
            Some((DEVICEID_KEY, value)) => device_id = Some(value),
            Some((SHAREDACCESSKEY_KEY, value)) => symmetric_key = Some(value),
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
