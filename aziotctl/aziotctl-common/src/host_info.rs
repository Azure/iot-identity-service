use std::env::consts::ARCH;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use nix::sys::utsname::UtsName;
use serde::Serialize;

/// A subset of the DMI variables exposed through /sys/devices/virtual/dmi/id.
///
/// Examples:
///
/// ```ignore
///  Host    | name            | version | vendor
/// ---------+-----------------+---------+-----------------------
///  Hyper-V | Virtual Machine | 7.0     | Microsoft Corporation
/// ```
///
/// Ref: <https://www.kernel.org/doc/html/latest/filesystems/sysfs.html>
#[derive(Clone, Debug, Serialize)]
pub struct DmiInfo {
    name: Option<String>,
    version: Option<String>,
    vendor: Option<String>,
}

impl Default for DmiInfo {
    fn default() -> Self {
        Self {
            name: try_read_dmi("product_name"),
            version: try_read_dmi("product_version"),
            vendor: try_read_dmi("sys_vendor"),
        }
    }
}

/// A subset of the fields from /etc/os-release.
///
/// Examples:
///
/// ```ignore
///  OS                  | id                  | version_id
/// ---------------------+---------------------+------------
///  CentOS 7            | centos              | 7
///  Debian 9            | debian              | 9
///  openSUSE Tumbleweed | opensuse-tumbleweed | 20190325
///  Ubuntu 18.04        | ubuntu              | 18.04
/// ```
///
/// Ref: <https://www.freedesktop.org/software/systemd/man/os-release.html>
#[derive(Clone, Debug, Serialize)]
pub struct OsInfo {
    id: Option<String>,
    version_id: Option<String>,
    pretty_name: Option<String>,
    arch: &'static str,
    bitness: usize,
}

impl Default for OsInfo {
    fn default() -> Self {
        let mut result = Self {
            id: None,
            version_id: None,
            pretty_name: None,
            arch: ARCH,
            // Technically wrong if someone runs an arm32 build on arm64,
            // but we have dedicated arm64 builds so hopefully they don't.
            bitness: std::mem::size_of::<usize>() * 8,
        };

        let os_release = fs::File::open("/etc/os-release")
            .or_else(|_| fs::File::open("/usr/lib/os-release"));

        if let Ok(os_release) = os_release {
            let os_release = io::BufReader::new(os_release);

            for line in os_release.lines() {
                if let Ok(line) = &line {
                    match parse_shell_line(line) {
                        Some(("ID", value)) => {
                            result.id = Some(value.to_owned());
                        },
                        Some(("VERSION_ID", value)) => {
                            result.version_id = Some(value.to_owned());
                        },
                        Some(("PRETTY_NAME", value)) => {
                            result.pretty_name = Some(value.to_owned());
                        },
                        _ => (),
                    };
                }
                else {
                    break;
                }
            }
        }

        result
    }
}

fn parse_shell_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();

    let (key, value) = line.split_once('=')?;

    // The value is essentially a shell string, so it can be quoted in single or
    // double quotes, and can have escaped sequences using backslash.
    // For simplicitly, just trim the quotes instead of implementing a full shell
    // string grammar.
    let value = if (value.starts_with('\'') && value.ends_with('\''))
        || (value.starts_with('"') && value.ends_with('"'))
    {
        &value[1..(value.len() - 1)]
    } else {
        value
    };

    Some((key, value))
}

fn try_read_dmi(entry: &'static str) -> Option<String> {
    let path = format!("/sys/devices/virtual/dmi/id/{}", entry);

    let bytes = fs::read(path).ok()?;

    Some(String::from_utf8(bytes)
        .ok()?
        .trim()
        .to_owned())
}
