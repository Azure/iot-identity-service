// Copyright (c) Microsoft. All rights reserved.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use nix::sys::stat as nix_stat;
use nix::unistd::{self, User};

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
    path: impl AsRef<Path>,
    user: &User,
    mode: u32,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    // Create `path` and all its parent directories.
    let () = fs::create_dir_all(path)
        .with_context(|| format!("could not create {} directory", path_displayable))?;

    // Enforce all parent directories of `path` are readable by `user`.
    if let Some(parent) = path.parent() {
        check_readable(parent, user, true)?;
    }

    // Set `path` itself to have the given owner and mode.
    let () = unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {} directory", path_displayable))?;
    let () = fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| {
        format!(
            "could not set permissions on {} directory",
            path_displayable
        )
    })?;

    Ok(())
}

pub fn write_file(
    path: impl AsRef<Path>,
    content: &[u8],
    user: &User,
    mode: u32,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = fs::write(path, content)
        .with_context(|| format!("could not create {}", path_displayable))?;
    let () = unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {}", path_displayable))?;
    let () = fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("could not set permissions on {}", path_displayable))?;

    Ok(())
}

/// Enforce `path` and its parent directories all the way to the root are readable by `user`,
/// by checking that at least one of these is true:
///
/// - The segment is world-readable.
/// - The segment is group-readable and `user.gid` is the group.
/// - The segment is owner-readable and `user.uid` is the owner.
///
/// Note that for directories, "readable" means r+x, not just r.
///
/// This is basically reimplementing `access(path, R_OK)` and `access(path, R_OK | X_OK)` but for the `user` user
/// instead of this process's user (which is root). The alternative would to spawn a child process as `user`
/// that does the `access` call. If we end up needing this pattern for more places in the codebase,
/// we can consider that option.
///
/// If a non-readable segment is found, the behavior of the function depends on the value of `fix`.
/// If `fix` is `false`, the function returns an error indicating which segment is not readable.
/// If `fix` is `true`, the function changes the mode of the segment to make it readable.
/// For files, the function makes the file owner-readable by the user.
/// For directories, the function makes the directory world-readable.
pub fn check_readable(mut path: &Path, user: &User, fix: bool) -> anyhow::Result<()> {
    loop {
        let nix_stat::FileStat {
            st_mode,
            st_uid,
            st_gid,
            ..
        } = nix_stat::stat(path).with_context(|| format!("could not stat {}", path.display()))?;

        let is_directory =
            st_mode & nix_stat::SFlag::S_IFMT.bits() == nix_stat::SFlag::S_IFDIR.bits();
        let readable_bits: nix_stat::mode_t = if is_directory { 0o4 | 0o1 } else { 0o4 };

        let is_world_readable = (st_mode & readable_bits) == readable_bits;
        let is_group_readable =
            st_mode & (readable_bits << 3) == (readable_bits << 3) && st_gid == user.gid.as_raw();
        let is_owner_readable =
            st_mode & (readable_bits << 6) == (readable_bits << 6) && st_uid == user.uid.as_raw();

        if !is_world_readable && !is_group_readable && !is_owner_readable {
            if fix {
                if is_directory {
                    // Make it world-readable
                    let () = fs::set_permissions(
                        path,
                        fs::Permissions::from_mode(st_mode | readable_bits),
                    )
                    .with_context(|| format!("could not set permissions on {}", path.display()))?;
                } else {
                    // Make it owner-readable by `user.uid`
                    let () =
                        unistd::chown(path, Some(user.uid), Some(user.gid)).with_context(|| {
                            format!("could not set ownership on {}", path.display())
                        })?;
                    let () = fs::set_permissions(
                        path,
                        fs::Permissions::from_mode(st_mode | (readable_bits << 6)),
                    )
                    .with_context(|| format!("could not set permissions on {}", path.display()))?;
                }
            } else {
                return Err(anyhow::anyhow!(
                    "{} is not readable by user {} (uid {}, gid {})",
                    path.display(),
                    user.name,
                    user.uid,
                    user.gid
                ));
            }
        }

        if let Some(parent) = path.parent() {
            path = parent;
        } else {
            break;
        }
    }

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
