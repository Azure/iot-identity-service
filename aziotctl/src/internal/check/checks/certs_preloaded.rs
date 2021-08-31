// Copyright (c) Microsoft. All rights reserved.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use serde::Serialize;
use url::Url;

use crate::internal::check::util::CertificateValidityExt;
use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
use crate::internal::common::CertificateValidity;

use aziot_certd_config::PreloadedCert;

#[derive(Serialize, Default)]
pub struct CertsPreloaded {}

#[async_trait::async_trait]
impl Checker for CertsPreloaded {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certs-preloaded",
            description: "preloaded certificates are valid",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl CertsPreloaded {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let preloaded_certs = &unwrap_or_skip!(&cache.cfg.certd).preloaded_certs;

        // TODO: Report warnings / errors for all certs in a single invocation of `check` rather than one at a time.
        // This requires changing the checker framework to support multiple CheckResults and Errors from a single check.

        let mut visited: BTreeMap<_, _> = Default::default();

        for id in preloaded_certs.keys() {
            match walk_preloaded_certs(id, preloaded_certs, &mut visited).await? {
                CheckResult::Ok => {}
                res => return Ok(res),
            }
        }

        Ok(CheckResult::Ok)
    }
}

#[async_recursion::async_recursion]
async fn walk_preloaded_certs<'a>(
    id: &'a str,
    preloaded_certs: &'a BTreeMap<String, PreloadedCert>,
    visited: &mut BTreeMap<&'a str, &'a Url>,
) -> Result<CheckResult> {
    match preloaded_certs.get(id) {
        Some(PreloadedCert::Uri(uri)) => match visited.insert(id, uri) {
            Some(previous_uri) if previous_uri != uri => {
                return Err(anyhow!(
                    "preloaded cert {:?} has been defined more than once",
                    id,
                ))
            }

            Some(_) => (),

            None => {
                if uri.scheme() != "file" {
                    return Err(anyhow!(
                        "preloaded cert {:?} has a scheme other than `file://`",
                        id,
                    ));
                }

                match CertificateValidity::new(uri.path(), "", id)
                    .await?
                    .to_check_result()?
                {
                    CheckResult::Ok => {}
                    res => return Ok(res),
                }
            }
        },

        Some(PreloadedCert::Ids(ids)) => {
            for id in ids {
                match walk_preloaded_certs(id, preloaded_certs, visited).await? {
                    CheckResult::Ok => {}
                    res => return Ok(res),
                }
            }
        }

        None => (),
    }

    Ok(CheckResult::Ok)
}
