// Copyright (c) Microsoft. All rights reserved.

use super::CheckResult;

pub trait CertificateValidityExt {
    fn to_check_result(&self) -> anyhow::Result<CheckResult>;
}

impl CertificateValidityExt for crate::internal::common::CertificateValidity {
    fn to_check_result(&self) -> anyhow::Result<CheckResult> {
        let now = chrono::Utc::now();
        if self.not_before > now {
            Err(anyhow::anyhow!(
                "{} '{}' has not-before time {} which is in the future",
                self.cert_name,
                self.cert_id,
                self.not_before,
            ))
        } else if self.not_after < now {
            Err(anyhow::anyhow!(
                "{} '{}' expired at {}",
                self.cert_name,
                self.cert_id,
                self.not_after,
            ))
        } else if self.not_after < now + chrono::Duration::days(7) {
            Ok(CheckResult::Warning(anyhow::anyhow!(
                "{} '{}' will expire soon ({}, in {} days)",
                self.cert_name,
                self.cert_id,
                self.not_after,
                (self.not_after - now).num_days(),
            )))
        } else {
            Ok(CheckResult::Ok)
        }
    }
}
