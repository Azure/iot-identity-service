// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
