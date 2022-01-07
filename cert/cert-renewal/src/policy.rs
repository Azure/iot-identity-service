// Copyright (c) Microsoft. All rights reserved.

/// Determines the policy for certificate renewal and retries.
#[derive(Clone, Debug, PartialEq)]
pub enum Policy {
    /// Renew and retry as a percentage of the certificate's lifetime.
    Percentage(f64),

    /// Renew and retry at fixed time intervals around expiry.
    Time(i64),
}

impl Policy {
    /// Provides the default cert renewal policy threshold.
    pub fn default_threshold() -> Self {
        // 80% of lifetime
        Policy::Percentage(0.8)
    }

    /// Determines if the provided policy is the default for thresholds.
    pub fn is_default_threshold(policy: &Policy) -> bool {
        policy == &Self::default_threshold()
    }

    /// Provides the default cert renewal retry period.
    pub fn default_retry() -> Self {
        // 4% of lifetime
        Policy::Percentage(0.04)
    }

    /// Determines if the provided policy is the default for retries.
    pub fn is_default_retry(policy: &Policy) -> bool {
        policy == &Self::default_retry()
    }

    /// Check if the given cert should be renewed based on this policy.
    pub fn should_renew(&self, cert: &openssl::x509::X509) -> bool {
        let not_before = cert.not_before();
        let not_after = cert.not_after();
        let now = now();

        // Cert not_after must be after not_before to be valid.
        // Always renew invalid certs.
        if not_before >= not_after {
            return true;
        }

        // Check for expired certificate. Renew if expired.
        if now >= not_after {
            return true;
        }

        match self {
            Policy::Percentage(threshold) => {
                let total_lifetime = not_before.diff(not_after).expect("valid times should diff");
                let total_lifetime = timediff_to_secs(&total_lifetime);

                let current_lifetime = not_before.diff(&now).expect("valid times should diff");
                let current_lifetime = timediff_to_secs(&current_lifetime);

                let lifetime = current_lifetime / total_lifetime;

                lifetime >= *threshold
            }

            Policy::Time(threshold) => {
                let expiry = asn1time_to_unix(not_after);
                let now = asn1time_to_unix(&now);

                expiry - now <= *threshold
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut policy: String = serde::Deserialize::deserialize(deserializer)?;

        let unit = if let Some(unit) = policy.pop() {
            unit
        } else {
            return Err(serde::de::Error::custom("policy not specified"));
        };

        let value: i64 = if let Ok(value) = policy.parse() {
            value
        } else {
            return Err(serde::de::Error::custom(
                "policy could not be parsed as number",
            ));
        };

        if value <= 0 {
            return Err(serde::de::Error::custom(
                "renewal policy values must be positive",
            ));
        }

        match unit {
            '%' => {
                if value >= 100 {
                    return Err(serde::de::Error::custom(
                        "lifetime percentage must be less than 100",
                    ));
                }

                // Rust doesn't have direct i64 to f64 conversion, so cast down to i32 first.
                // This will never fail because 0 < value < 100.
                let value: i32 = std::convert::TryFrom::try_from(value).unwrap();
                let value: f64 = std::convert::From::from(value);

                Ok(Policy::Percentage(value / 100.0))
            }
            'm' => Ok(Policy::Time(value * 60)),
            'd' => Ok(Policy::Time(value * 86400)),
            _ => Err(serde::de::Error::custom("bad units for policy")),
        }
    }
}

impl serde::Serialize for Policy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let policy = match self {
            Policy::Percentage(percentage) => {
                let percentage = percentage * 100.0;

                format!("{:.0}%", percentage)
            }
            Policy::Time(time) => {
                // Represent time as whole days if possible, otherwise as minutes.
                if time % 86400 == 0 {
                    let days = time / 86400;

                    format!("{}d", days)
                } else {
                    let minutes = time / 60;

                    format!("{}m", minutes)
                }
            }
        };

        policy.serialize(serializer)
    }
}

fn asn1time_to_unix(time: &openssl::asn1::Asn1TimeRef) -> i64 {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).expect("unix epoch should be valid");
    let unix = epoch.diff(time).expect("valid times should diff");

    i64::from(unix.days) * 86400 + i64::from(unix.secs)
}

fn timediff_to_secs(diff: &openssl::asn1::TimeDiff) -> f64 {
    // This function is only called for diffs that should be non-negative.
    assert!(diff.days >= 0);
    assert!(diff.secs >= 0);

    f64::from(diff.days) * 86400.0 + f64::from(diff.secs)
}

#[cfg(not(test))]
fn now() -> openssl::asn1::Asn1Time {
    openssl::asn1::Asn1Time::days_from_now(0).expect("current time should be valid")
}

// Mocks the current time for testing.
#[cfg(test)]
fn now() -> openssl::asn1::Asn1Time {
    let time = tests::CURRENT_TIME.load(std::sync::atomic::Ordering::Acquire);

    openssl::asn1::Asn1Time::from_unix(time).expect("invalid time")
}

#[cfg(test)]
mod tests {
    use super::Policy;

    // Tests that modify this value must be run serially.
    pub(super) static CURRENT_TIME: std::sync::atomic::AtomicI64 =
        std::sync::atomic::AtomicI64::new(0);

    fn set_time(time: i64) {
        CURRENT_TIME.store(time, std::sync::atomic::Ordering::Release);
    }

    fn generate_cert(not_before: i64, not_after: i64) -> openssl::x509::X509 {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let private_key = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        let public_key = private_key.public_key_to_pem().unwrap();
        let public_key = openssl::pkey::PKey::public_key_from_pem(&public_key).unwrap();

        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_version(2).unwrap();

        let mut name = openssl::x509::X509Name::builder().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "test_cert")
            .unwrap();
        let name = name.build();

        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();

        let not_before = openssl::asn1::Asn1Time::from_unix(not_before).unwrap();
        cert.set_not_before(&not_before).unwrap();

        let not_after = openssl::asn1::Asn1Time::from_unix(not_after).unwrap();
        cert.set_not_after(&not_after).unwrap();

        cert.set_pubkey(&public_key).unwrap();
        cert.sign(&private_key, openssl::hash::MessageDigest::sha256())
            .unwrap();

        cert.build()
    }

    #[test]
    fn deserialize_ok() {
        // Percentage lifetime.
        let input = toml::Value::String("90%".to_string());
        let policy: Policy = serde::Deserialize::deserialize(input).unwrap();
        assert_eq!(Policy::Percentage(0.9), policy);

        // Time in minutes.
        let input = toml::Value::String("100m".to_string());
        let policy: Policy = serde::Deserialize::deserialize(input).unwrap();
        assert_eq!(Policy::Time(100 * 60), policy);

        // Time in days.
        let input = toml::Value::String("10d".to_string());
        let policy: Policy = serde::Deserialize::deserialize(input).unwrap();
        assert_eq!(Policy::Time(10 * 86400), policy);
    }

    #[test]
    fn deserialize_err() {
        // Empty policy.
        let input = toml::Value::String("".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Non-numeric value.
        let input = toml::Value::String("a%".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Bad units.
        let input = toml::Value::String("1y".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Lifetime percentage too high.
        let input = toml::Value::String("101%".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Lifetime percentage too low.
        let input = toml::Value::String("0%".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Invalid time.
        let input = toml::Value::String("0m".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();
    }

    #[test]
    fn serialize() {
        let input = Policy::Percentage(0.8);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"80%\"", result);

        let input = Policy::Percentage(0.89);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"89%\"", result);

        let input = Policy::Time(2 * 60);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"2m\"", result);

        let input = Policy::Time(86460);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"1441m\"", result);

        let input = Policy::Time(3 * 86400);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"3d\"", result);
    }

    #[test]
    fn bad_cert() {
        // Bad cert: not_after is before not_before.
        let cert = generate_cert(5, 1);

        let policy = Policy::Percentage(100.0);
        assert!(policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn expired_cert() {
        // Cert expired at t=5 when current time is t=6.
        let cert = generate_cert(1, 5);
        set_time(6);

        let policy = Policy::Percentage(100.0);
        assert!(policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn policy_percentage() {
        // Test calculation with negative timestamps.
        let cert = generate_cert(-5, -1);
        set_time(-3);

        let policy = Policy::Percentage(0.4);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.5);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.6);
        assert!(!policy.should_renew(&cert));

        // Test calculation with mixed timestamps.
        let cert = generate_cert(-2, 2);
        set_time(0);

        let policy = Policy::Percentage(0.4);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.5);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.6);
        assert!(!policy.should_renew(&cert));

        // Test calculation with positive timestamps.
        let cert = generate_cert(1, 5);
        set_time(3);

        let policy = Policy::Percentage(0.4);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.5);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(0.6);
        assert!(!policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn policy_time() {
        // Test calculation with negative timestamps.
        let cert = generate_cert(-5, -1);
        set_time(-3);

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));

        // Test calculation with mixed timestamps.
        let cert = generate_cert(-2, 2);
        set_time(0);

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));

        // Test calculation with positive timestamps.
        let cert = generate_cert(1, 5);
        set_time(3);

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));
    }
}
