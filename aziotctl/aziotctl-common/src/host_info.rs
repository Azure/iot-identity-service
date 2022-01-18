// Copyright (c) Microsoft. All rights reserved.

use std::env::consts::ARCH;
use std::fs;
use std::io::{self, BufRead};

use serde::Serialize;
use serde_with::skip_serializing_none;

#[cfg(target_pointer_width = "32")]
const BITNESS: usize = 32;
#[cfg(target_pointer_width = "64")]
const BITNESS: usize = 64;
#[cfg(target_pointer_width = "128")]
const BITNESS: usize = 128;

/// A subset of the DMI variables exposed through /sys/devices/virtual/dmi/id.
///
/// Examples:
///
/// ```ignore
///  Host    | name            | vendor
/// ---------+-----------------+-----------------------
///  Hyper-V | Virtual Machine | Microsoft Corporation
/// ```
///
/// Ref: <https://www.kernel.org/doc/html/latest/filesystems/sysfs.html>
#[derive(Clone, Debug, Serialize)]
pub struct DmiInfo {
    pub product: Option<String>,
    pub vendor: Option<String>,
}

impl Default for DmiInfo {
    fn default() -> Self {
        Self {
            product: try_read_dmi("product_name"),
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
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize)]
pub struct OsInfo {
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub arch: &'static str,
    pub bitness: usize,
}

impl Default for OsInfo {
    fn default() -> Self {
        let mut result = Self {
            id: None,
            version_id: None,
            arch: ARCH,
            bitness: BITNESS,
        };

        let os_release =
            fs::File::open("/etc/os-release").or_else(|_| fs::File::open("/usr/lib/os-release"));

        if let Ok(os_release) = os_release {
            let os_release = io::BufReader::new(os_release);

            for line in os_release.lines() {
                if let Ok(line) = &line {
                    match parse_shell_line(line) {
                        Some(("ID", value)) => {
                            result.id = Some(value.to_owned());
                        }
                        Some(("VERSION_ID", value)) => {
                            result.version_id = Some(value.to_owned());
                        }
                        _ => (),
                    };
                } else {
                    break;
                }
            }
        }

        result
    }
}

pub fn parse_shell_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();

    let pos = line.find('=')?;
    let (key, value) = (&line[..pos], &line[pos+1..]);

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

    Some(std::str::from_utf8(&bytes).ok()?.trim().to_owned())
}
