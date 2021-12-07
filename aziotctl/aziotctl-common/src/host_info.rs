use std::convert::TryFrom;
use std::env::consts::ARCH;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

use nix::sys::utsname::UtsName;
use serde::{Deserialize, Serialize};

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
                    match parse_os_release_line(line) {
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

fn parse_os_release_line(line: &str) -> Option<(&str, &str)> {
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

pub struct HardwareInfo {
    name: Option<String>,
    version: Option<String>,
    vendor: Option<String>,
}

impl Default for HardwareInfo {
    fn default() -> Self {
        Self {
            name: try_read_dmi("product_name"),
            version: try_read_dmi("product_version"),
            vendor: try_read_dmi("sys_vendor"),
        }
    }
}

fn try_read_dmi(entry: &'static str) -> Option<String> {
    let path = format!("/sys/devices/virtual/dmi/id/{}", entry);

    let bytes = fs::read(path).ok()?;

    Some(String::from_utf8(bytes)
        .ok()?
        .trim()
        .to_owned())
}

#[derive(Debug, Deserialize, PartialEq)]
struct Product {
    name: String,
    version: String,
    comment: Option<String>,
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)?;

        if let Some(comment) = &self.comment {
            write!(f, " ({})", comment)?;
        };

        Ok(())
    }
}

impl From<UtsName> for Product {
    fn from(value: UtsName) -> Self {
        Self {
            name: value.sysname().to_owned(),
            version: value.release().to_owned(),
            comment: Some(value.version().to_owned()),
        }
    }
}

impl From<OsInfo> for Product {
    fn from(value: OsInfo) -> Self {
        Self {
            name: value.id.unwrap_or_else(|| "UNKNOWN_OS".to_owned()),
            version: value.version_id.unwrap_or_else(|| "UNKNOWN_OS_VERSION".to_owned()),
            comment: value.pretty_name,
        }
    }
}

impl From<HardwareInfo> for Product {
    fn from(value: HardwareInfo) -> Self {
        Self {
            name: value.name.unwrap_or_else(|| "UNKNOWN_HARDWARE".to_owned()),
            version: value.version.unwrap_or_else(|| "UNKNOWN_HARDWARE_VERSION".to_owned()),
            comment: value.vendor
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "PathBuf")]
pub struct ProductInfo {
    product: Vec<Product>,
}

impl TryFrom<PathBuf> for ProductInfo {
    type Error = io::Error;

    fn try_from(p: PathBuf) -> Result<Self, Self::Error> {
        let bytes = fs::read(p)?;

        toml::de::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl fmt::Display for ProductInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut products = self.product.iter();

        if let Some(first) = products.next() {
            write!(f, "{}", first)?;

            for product in products {
                write!(f, " {}", product)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl From<(&str, &str)> for Product {
        fn from(value: (&str, &str)) -> Self {
            Product {
                name: value.0.to_owned(),
                version: value.1.to_owned(),
                comment: None,
            }
        }
    }

    impl From<(&str, &str, &str)> for Product {
        fn from(value: (&str, &str, &str)) -> Self {
            Product {
                name: value.0.to_owned(),
                version: value.1.to_owned(),
                comment: Some(value.2.to_owned()),
            }
        }
    }

    #[test]
    fn product_string_no_comment() {
        let p: Product = ("FOO", "BAR").into();

        assert_eq!("FOO/BAR", p.to_string());
    }

    #[test]
    fn product_string_with_comment() {
        let p: Product = ("FOO", "BAR", "BAZ").into();

        assert_eq!("FOO/BAR (BAZ)", p.to_string());
    }

    #[test]
    fn multiple_products() {
        let pinfo = ProductInfo {
            product: vec![
                ("FOO", "BAR").into(),
                ("A", "B", "C").into(),
                ("name", "version", "comment").into(),
            ],
        };

        assert_eq!("FOO/BAR A/B (C) name/version (comment)", pinfo.to_string());
    }
}
