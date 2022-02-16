// Copyright (c) Microsoft. All rights reserved.

use anyhow::anyhow;
use serde::Serialize;

use aziotctl_common::check_last_modified::{check_last_modified, LastModifiedError};

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

    #[allow(clippy::unused_async)]
    async fn execute(&mut self, _shared: &CheckerShared, _cache: &mut CheckerCache) -> CheckResult {
        match check_last_modified(&["keyd", "certd", "identityd", "tpmd"]) {
            Ok(()) => CheckResult::Ok,
            Err(LastModifiedError::Ignored) => CheckResult::Ignored,
            Err(LastModifiedError::Warning(message)) => CheckResult::Warning(anyhow!(message)),
            Err(LastModifiedError::Failed(error)) => CheckResult::Failed(error.into()),
        }
    }
}
