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

pub mod config;
mod restart;
mod set_log_level;
mod status;
mod system_logs;

pub use restart::restart;
pub use set_log_level::set_log_level;
pub use status::get_status;
pub use system_logs::get_system_logs;

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

pub struct ServiceDefinition {
    pub service: &'static str,
    pub sockets: &'static [&'static str],
}

// Note, the ordering is important, since the first service is considered the root and will be started by the restart command.
pub const SERVICE_DEFINITIONS: &[&ServiceDefinition] = &[
    &ServiceDefinition {
        service: "aziot-identityd.service",
        sockets: &["aziot-identityd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-keyd.service",
        sockets: &["aziot-keyd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-certd.service",
        sockets: &["aziot-certd.socket"],
    },
    &ServiceDefinition {
        service: "aziot-tpmd.service",
        sockets: &["aziot-tpmd.socket"],
    },
];

pub fn hostname() -> anyhow::Result<String> {
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

pub fn program_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|arg| arg.into_string().ok())
        .unwrap_or_else(|| "<current program>".to_owned())
}
