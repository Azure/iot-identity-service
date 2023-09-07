// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use std::collections::BTreeMap;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub mod check_last_modified;
pub mod config;
pub mod host_info;
pub mod system;

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResultsSerializable {
    pub additional_info: serde_json::Value,
    pub checks: BTreeMap<String, CheckOutputSerializable>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result")]
#[serde(rename_all = "snake_case")]
pub enum CheckResultSerializable {
    Ok,
    Warning { details: Vec<String> },
    Ignored,
    Skipped,
    Fatal { details: Vec<String> },
    Error { details: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckOutputSerializable {
    pub result: CheckResultSerializable,
    pub additional_info: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
pub enum CheckOutputSerializableStreaming {
    AdditionalInfo(serde_json::Value),
    Section {
        name: String,
    },
    Check {
        #[serde(flatten)]
        meta: CheckerMetaSerializable,
        #[serde(flatten)]
        output: CheckOutputSerializable,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckerMetaSerializable {
    /// Unique human-readable identifier for the check.
    pub id: String,
    /// A brief description of what this check does.
    pub description: String,
}

/// Keys are section names
pub type CheckListOutput = BTreeMap<String, Vec<CheckerMetaSerializable>>;

pub fn hostname() -> anyhow::Result<String> {
    if cfg!(test) {
        Ok("my-device".to_owned())
    } else {
        let hostname = nix::unistd::gethostname().context("could not get machine hostname")?;
        let hostname = hostname
            .to_str()
            .context("could not get machine hostname")?;
        Ok(hostname.to_owned())
    }
}

pub fn check_length_for_local_issuer(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 64 {
        return false;
    }

    true
}

pub fn is_rfc_1035_valid(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 255 {
        return false;
    }

    let mut labels = hostname.split('.');

    let all_labels_valid = labels.all(|label| {
        if label.len() > 63 {
            return false;
        }

        let first_char = match label.chars().next() {
            Some(c) => c,
            None => return false,
        };
        if !first_char.is_ascii_alphabetic() {
            return false;
        }

        if label
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-')
        {
            return false;
        }

        let last_char = label
            .chars()
            .last()
            .expect("label has at least one character");
        if !last_char.is_ascii_alphanumeric() {
            return false;
        }

        true
    });
    if !all_labels_valid {
        return false;
    }

    true
}

fn program_name() -> String {
    std::env::current_exe()
        .expect("Cannot get the exec path")
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("<current program>").to_owned()
}

#[cfg(test)]
mod tests {
    use super::{check_length_for_local_issuer, is_rfc_1035_valid};

    #[test]
    fn test_check_length_for_local_issuer() {
        let longest_valid_label = "a".repeat(64);
        assert!(check_length_for_local_issuer(&longest_valid_label));

        let invalid_label = "a".repeat(65);
        assert!(!check_length_for_local_issuer(&invalid_label));
    }

    #[test]
    fn test_is_rfc_1035_valid() {
        let longest_valid_label = "a".repeat(63);
        let longest_valid_name = format!(
            "{label}.{label}.{label}.{label_rest}",
            label = longest_valid_label,
            label_rest = "a".repeat(255 - 63 * 3 - 3)
        );
        assert_eq!(longest_valid_name.len(), 255);

        assert!(is_rfc_1035_valid("foobar"));
        assert!(is_rfc_1035_valid("foobar.baz"));
        assert!(is_rfc_1035_valid(&longest_valid_label));
        assert!(is_rfc_1035_valid(&format!(
            "{label}.{label}.{label}",
            label = longest_valid_label
        )));
        assert!(is_rfc_1035_valid(&longest_valid_name));
        assert!(is_rfc_1035_valid("xn--v9ju72g90p.com"));
        assert!(is_rfc_1035_valid("xn--a-kz6a.xn--b-kn6b.xn--c-ibu"));

        assert!(is_rfc_1035_valid("FOOBAR"));
        assert!(is_rfc_1035_valid("FOOBAR.BAZ"));
        assert!(is_rfc_1035_valid("FoObAr01.bAz"));

        assert!(!is_rfc_1035_valid(&format!("{}a", longest_valid_label)));
        assert!(!is_rfc_1035_valid(&format!("{}a", longest_valid_name)));
        assert!(!is_rfc_1035_valid("01.org"));
        assert!(!is_rfc_1035_valid("\u{4eca}\u{65e5}\u{306f}"));
        assert!(!is_rfc_1035_valid("\u{4eca}\u{65e5}\u{306f}.com"));
        assert!(!is_rfc_1035_valid("a\u{4eca}.b\u{65e5}.c\u{306f}"));
        assert!(!is_rfc_1035_valid("FoObAr01.bAz-"));
    }
}
