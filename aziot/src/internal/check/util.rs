// Copyright (c) Microsoft. All rights reserved.

use anyhow::anyhow;
use chrono::TimeZone;

use crate::internal::common::CertificateValidity;

use super::CheckResult;

pub trait CertificateValidityExt {
    fn to_check_result(&self) -> anyhow::Result<CheckResult>;
}

impl CertificateValidityExt for CertificateValidity {
    fn to_check_result(&self) -> anyhow::Result<CheckResult> {
        let y2038 = chrono::Utc.timestamp(i64::from(std::u32::MAX), 0);
        let y2050 = chrono::Utc.ymd(2050, 1, 1).and_hms(0, 0, 0);

        let now = chrono::Utc::now();
        if self.not_before > now {
            Err(anyhow!(
                "{} '{}' has not-before time {} which is in the future",
                self.cert_name,
                self.cert_id,
                self.not_before,
            ))
        } else if self.not_after < now {
            Err(anyhow!(
                "{} '{}' expired at {}",
                self.cert_name,
                self.cert_id,
                self.not_after,
            ))
        } else if self.not_after < now + chrono::Duration::days(7) {
            Ok(CheckResult::Warning(anyhow!(
                "{} '{}' will expire soon ({}, in {} days)",
                self.cert_name,
                self.cert_id,
                self.not_after,
                (self.not_after - now).num_days(),
            )))
        } else if std::mem::size_of::<nix::sys::time::time_t>() == std::mem::size_of::<u32>()
            && self.not_after > y2038
        {
            Ok(CheckResult::Warning(anyhow!(
                "{} '{}' expires on {}. Expiration dates >=2038 are not supported on systems where time_t is 32-bits",
                self.cert_name,
                self.cert_id,
                self.not_after,
            )))
        } else if self.not_after > y2050 {
            // See https://github.com/Azure/iotedge/issues/1960
            // and https://github.com/Azure/iotedge/pull/2234
            Ok(CheckResult::Warning(anyhow!(
                "{} '{}' expires on {}. Expiration dates >=2050 are not currently supported",
                self.cert_name,
                self.cert_id,
                self.not_after,
            )))
        } else {
            Ok(CheckResult::Ok)
        }
    }
}
