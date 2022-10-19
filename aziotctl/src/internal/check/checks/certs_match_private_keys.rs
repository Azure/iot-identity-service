// Copyright (c) Microsoft. All rights reserved.

use std::fmt::Write;

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct CertsMatchPrivateKeys {}

#[async_trait::async_trait]
impl Checker for CertsMatchPrivateKeys {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certs-match-private-keys",
            description:
                "ensure all preloaded certificates match preloaded private keys with the same ID",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        Self::inner_execute(shared, cache).unwrap_or_else(CheckResult::Failed)
    }
}

impl CertsMatchPrivateKeys {
    fn inner_execute(_shared: &CheckerShared, cache: &mut CheckerCache) -> Result<CheckResult> {
        if !cache.daemons_running.certd || !cache.daemons_running.keyd {
            return Ok(CheckResult::Skipped);
        }

        let mut err_aggregated = String::new();

        for (id, private_key) in &cache.private_keys {
            if let Some(cert) = cache.certs.get(id) {
                unsafe {
                    let result = openssl2::openssl_returns_1(openssl_sys2::X509_check_private_key(
                        foreign_types_shared::ForeignType::as_ptr(cert),
                        foreign_types_shared::ForeignType::as_ptr(private_key),
                    ));
                    if result.is_err() {
                        if !err_aggregated.is_empty() {
                            err_aggregated.push('\n');
                        }
                        write!(
                            &mut err_aggregated,
                            "preloaded cert with ID {:?} does not match preloaded private key with ID {:?}",
                            id,
                            id
                        ).expect("std::fmt::Write for String should not fail");
                    }
                }
            }
        }

        if err_aggregated.is_empty() {
            Ok(CheckResult::Ok)
        } else {
            Err(anyhow!("{}", err_aggregated))
        }
    }
}
