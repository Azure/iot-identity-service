// Copyright (c) Microsoft. All rights reserved.

//! Request/Response types used by the TPM Service's HTTP API.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::wildcard_imports)] // to use `super::*`

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiVersion {
    V2020_10_15,
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ApiVersion::V2020_10_15 => "2020-10-15",
        })
    }
}

impl std::str::FromStr for ApiVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2020-10-15" => Ok(ApiVersion::V2020_10_15),
            _ => Err(()),
        }
    }
}

pub mod get_tpm_keys {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Request {}

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Response {
        /// The TPM's Endorsement Key
        pub endorsement_key: http_common::ByteString,
        /// The TPM's Storage Root Key
        pub storage_root_key: http_common::ByteString,
    }
}
