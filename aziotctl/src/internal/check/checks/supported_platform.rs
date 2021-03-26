// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct SupportedPlatform {}

#[async_trait::async_trait]
impl Checker for SupportedPlatform {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "supported-platform",
            description: "production readiness: running on supported platform",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl SupportedPlatform {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        _cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use os_info::{Type, Version};

        enum Tier {
            Tier1,
            Tier2,
            Tier3,
        }

        let info = os_info::get();
        let tier = match info.os_type() {
            Type::CentOS | Type::Debian | Type::Ubuntu => {
                if match info.os_type() {
                    Type::CentOS => {
                        matches!(info.version(), Version::Custom(v) if v == "7")
                    }
                    Type::Debian => {
                        matches!(info.version(), Version::Custom(v) if v == "9" || v == "10")
                    }
                    Type::Ubuntu => {
                        matches!(info.version(), Version::Custom(v) if v == "20.04" || v == "18.04")
                    }
                    _ => unreachable!(),
                } {
                    Tier::Tier1
                } else {
                    Tier::Tier2
                }
            }
            Type::Alpine
            | Type::Amazon
            | Type::Arch
            | Type::Fedora
            | Type::Linux
            | Type::Manjaro
            | Type::Mint
            | Type::openSUSE
            | Type::OracleLinux
            | Type::Pop
            | Type::Redhat
            | Type::RedHatEnterprise
            | Type::SUSE => Tier::Tier2,
            _ => Tier::Tier3,
        };

        Ok(match tier {
            Tier::Tier1 => CheckResult::Ok,
            Tier::Tier2 => CheckResult::Warning(anyhow!(
                "Running on a partially supported, Tier 2 platform ({}). lorem ipsum",
                info
            )),
            Tier::Tier3 => CheckResult::Warning(anyhow!(
                "Running on an unsupported, Tier 3 platform ({}). lorem ipsum",
                info
            )),
        })
    }
}
