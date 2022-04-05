// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

mod cert_interface;
pub use cert_interface::CertInterface;

#[cfg(test)]
use cert_interface::TestInterface;

mod credential;
use credential::{Credential, CredentialHeap};

pub mod engine;
pub use engine::RenewalEngine;

pub mod error;
pub use error::Error;

pub mod policy;
pub use policy::{Policy, RenewalPolicy};

mod time;
use time::Time;

#[cfg(test)]
use time::test_time;

/// Common function for generating test credentials.
#[cfg(test)]
fn test_cert(not_before: i64, not_after: i64) -> openssl::x509::X509 {
    let (cert, _) = test_common::credential::custom_test_certificate("test_cert", |cert| {
        let not_before = openssl::asn1::Asn1Time::from_unix(not_before).unwrap();
        let not_after = openssl::asn1::Asn1Time::from_unix(not_after).unwrap();

        cert.set_not_before(&not_before).unwrap();
        cert.set_not_after(&not_after).unwrap();
    });

    cert
}

/// Common settings for configuring auto-renewal.
#[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AutoRenewConfig {
    /// Whether to rotate the key. This requires temporary storage for a second
    /// key during credential rotation. Defaults to `true`.
    pub rotate_key: bool,

    /// Renewal policy.
    #[serde(flatten)]
    pub policy: RenewalPolicy,
}

impl Default for AutoRenewConfig {
    fn default() -> Self {
        AutoRenewConfig {
            rotate_key: true,
            policy: RenewalPolicy {
                threshold: Policy::Percentage(80),
                retry: Policy::Percentage(4),
            },
        }
    }
}

impl AutoRenewConfig {
    pub fn is_default(&self) -> bool {
        self == &AutoRenewConfig::default()
    }
}
