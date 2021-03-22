// Copyright (c) Microsoft. All rights reserved.

use anyhow::{Context, Result};
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
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl CertsMatchPrivateKeys {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        for (id, private_key) in &cache.private_keys {
            if let Some(cert) = cache.certs.get(id) {
                unsafe {
                    openssl2::openssl_returns_1(openssl_sys2::X509_check_private_key(
                        foreign_types_shared::ForeignType::as_ptr(cert),
                        foreign_types_shared::ForeignType::as_ptr(private_key),
                    )).with_context(|| format!("preloaded cert with ID {:?} does not match preloaded private key with ID {:?}", id, id))?;
                }
            }
        }

        Ok(CheckResult::Ok)
    }
}
