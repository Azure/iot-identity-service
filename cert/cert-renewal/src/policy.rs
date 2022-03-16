// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RenewalPolicy {
    pub threshold: Policy,
    pub retry: Policy,
}

/// Determines the policy for certificate renewal and retries.
#[derive(Clone, Debug, PartialEq)]
pub enum Policy {
    /// Renew and retry as a percentage of the certificate's lifetime.
    /// This value is always between 0 and 100.
    Percentage(i64),

    /// Renew and retry at fixed time intervals around expiry.
    Time(i64),
}

impl Policy {
    /// Check if the given cert should be renewed based on this policy.
    pub fn should_renew(&self, cert: &openssl::x509::X509) -> bool {
        let not_before = crate::Time::from(cert.not_before());
        let not_after = crate::Time::from(cert.not_after());

        // Cert not_after must be after not_before to be valid.
        // Always renew invalid certs.
        if not_before >= not_after {
            return true;
        }

        // Check for expired certificate. Renew if expired.
        if not_after.in_past() {
            return true;
        }

        match self {
            Policy::Percentage(threshold) => {
                let total_lifetime = not_after - not_before;
                let current_lifetime = crate::Time::now() - not_before;

                let lifetime = current_lifetime * 100 / total_lifetime;

                lifetime >= *threshold
            }

            Policy::Time(threshold) => not_after - crate::Time::now() <= *threshold,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut policy: String = serde::Deserialize::deserialize(deserializer)?;

        let last = if let Some(last) = policy.pop() {
            last
        } else {
            return Err(serde::de::Error::custom("policy not specified"));
        };

        let mut unit = last.to_string();

        // Parse for "min" or "day".
        if last == 'n' || last == 'y' {
            if let Some(last) = policy.pop() {
                unit.insert(0, last);
            } else {
                return Err(serde::de::Error::custom("bad units for policy"));
            }

            if let Some(last) = policy.pop() {
                unit.insert(0, last);
            } else {
                return Err(serde::de::Error::custom("bad units for policy"));
            }
        }

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

        match unit.as_str() {
            "%" => {
                if value >= 100 {
                    return Err(serde::de::Error::custom(
                        "lifetime percentage must be less than 100",
                    ));
                }

                Ok(Policy::Percentage(value))
            }
            "min" => Ok(Policy::Time(value * 60)),
            "day" => Ok(Policy::Time(value * 86400)),
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
                format!("{}%", percentage)
            }
            Policy::Time(time) => {
                // Represent time as whole days if possible, otherwise as minutes.
                if time % 86400 == 0 {
                    let days = time / 86400;

                    format!("{}day", days)
                } else {
                    let minutes = time / 60;

                    format!("{}min", minutes)
                }
            }
        };

        policy.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_cert;

    use super::Policy;

    #[test]
    fn deserialize_ok() {
        // Percentage lifetime.
        let input = toml::Value::String("90%".to_string());
        let policy: Policy = serde::Deserialize::deserialize(input).unwrap();
        assert_eq!(Policy::Percentage(90), policy);

        // Time in minutes.
        let input = toml::Value::String("100min".to_string());
        let policy: Policy = serde::Deserialize::deserialize(input).unwrap();
        assert_eq!(Policy::Time(100 * 60), policy);

        // Time in days.
        let input = toml::Value::String("10day".to_string());
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

        // Missing value.
        let input = toml::Value::String("day".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();

        // Bad units.
        let input = toml::Value::String("1year".to_string());
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
        let input = toml::Value::String("0min".to_string());
        let err: Result<Policy, toml::de::Error> = serde::Deserialize::deserialize(input);
        err.unwrap_err();
    }

    #[test]
    fn serialize() {
        let input = Policy::Percentage(80);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"80%\"", result);

        let input = Policy::Percentage(89);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"89%\"", result);

        let input = Policy::Time(2 * 60);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"2min\"", result);

        let input = Policy::Time(86460);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"1441min\"", result);

        let input = Policy::Time(3 * 86400);
        let result = toml::to_string(&input).unwrap();
        assert_eq!("\"3day\"", result);
    }

    #[test]
    fn bad_cert() {
        // Bad cert: not_after is before not_before.
        let cert = test_cert(5, 1);

        let policy = Policy::Percentage(100);
        assert!(policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn expired_cert() {
        // Cert expired at t=5 when current time is t=6.
        let cert = test_cert(1, 5);
        crate::test_time::set(6);

        let policy = Policy::Percentage(100);
        assert!(policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn policy_percentage() {
        crate::test_time::reset();

        // Test calculation with negative timestamps.
        let cert = test_cert(-5, -1);
        crate::test_time::set(-3);

        let policy = Policy::Percentage(40);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(50);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(60);
        assert!(!policy.should_renew(&cert));

        // Test calculation with mixed timestamps.
        let cert = test_cert(-2, 2);
        crate::test_time::reset();

        let policy = Policy::Percentage(40);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(50);
        assert!(policy.should_renew(&cert));

        let policy = Policy::Percentage(60);
        assert!(!policy.should_renew(&cert));

        // Test calculation with positive timestamps.
        let cert = test_cert(1, 5);
        crate::test_time::set(3);

        let policy = Policy::Percentage(40);
        assert!(policy.should_renew(&cert));
        let policy = Policy::Percentage(50);
        assert!(policy.should_renew(&cert));
        let policy = Policy::Percentage(60);
        assert!(!policy.should_renew(&cert));
    }

    #[test]
    #[serial_test::serial]
    fn policy_time() {
        // Test calculation with negative timestamps.
        let cert = test_cert(-5, -1);
        crate::test_time::set(-3);

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));

        // Test calculation with mixed timestamps.
        let cert = test_cert(-2, 2);
        crate::test_time::reset();

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));

        // Test calculation with positive timestamps.
        let cert = test_cert(1, 5);
        crate::test_time::set(3);

        // Renewal policy of "within 1": should not renew.
        let policy = Policy::Time(1);
        assert!(!policy.should_renew(&cert));

        // Renewal policy of "within 3": should renew.
        let policy = Policy::Time(3);
        assert!(policy.should_renew(&cert));
    }
}
