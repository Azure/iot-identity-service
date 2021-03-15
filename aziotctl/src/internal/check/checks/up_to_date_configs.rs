// Copyright (c) Microsoft. All rights reserved.

use anyhow::anyhow;
use serde::Serialize;

use aziotctl_common::check_last_modified::check_last_modified;
use aziotctl_common::check_last_modified::CheckResult as InternalCheckResult;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct UpToDateConfigs {}

#[async_trait::async_trait]
impl Checker for UpToDateConfigs {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "configs-up-to-date",
            description: "daemon configurations up-to-date with config.toml",
        }
    }

    async fn execute(&mut self, _shared: &CheckerShared, _cache: &mut CheckerCache) -> CheckResult {
        match check_last_modified(&["keyd", "certd", "identityd", "tpmd"]) {
            InternalCheckResult::Ok => CheckResult::Ok,
            InternalCheckResult::Ignored => CheckResult::Ignored,
            InternalCheckResult::Warning(message) => CheckResult::Warning(anyhow!(message)),
            InternalCheckResult::Failed(error) => CheckResult::Failed(error.into())
        }
    }
}
