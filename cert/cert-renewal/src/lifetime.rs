// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug, PartialEq)]
pub enum Lifetime {
    Valid(f64),
    Expired,
    BadCert,
}

impl Lifetime {
    #[must_use]
    pub fn from_cert(cert: &openssl::x509::X509) -> Self {
        let not_before = cert.not_before();
        let not_after = cert.not_after();
        let now = now();

        // Cert not_after must be after not_before.
        if not_before >= not_after {
            return Lifetime::BadCert;
        }

        // Check for expired certificate.
        if now >= not_after {
            return Lifetime::Expired;
        }

        let total_lifetime = not_before.diff(not_after).expect("valid times should diff");
        let total_lifetime = timediff_to_secs(&total_lifetime);

        let current_lifetime = not_before.diff(&now).expect("valid times should diff");
        let current_lifetime = timediff_to_secs(&current_lifetime);

        let lifetime = current_lifetime / total_lifetime;

        Lifetime::Valid(lifetime)
    }

    #[must_use]
    pub fn should_renew(&self, threshold: f64) -> bool {
        if let Lifetime::Valid(lifetime) = self {
            lifetime >= &threshold
        } else {
            // Always renew expired or invalid certificates.
            true
        }
    }
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

#[cfg(test)]
// Mocks the current time for testing.
fn now() -> openssl::asn1::Asn1Time {
    let time = tests::CURRENT_TIME.load(std::sync::atomic::Ordering::Acquire);

    openssl::asn1::Asn1Time::from_unix(time).expect("invalid time")
}

#[cfg(test)]
mod tests {
    use super::Lifetime;

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
    #[serial_test::serial]
    fn bad_cert() {
        // Bad cert: not_after is before not_before.
        let cert = generate_cert(5, 1);
        let lifetime = Lifetime::from_cert(&cert);

        assert_eq!(Lifetime::BadCert, lifetime);
        assert!(lifetime.should_renew(100.0));
    }

    #[test]
    #[serial_test::serial]
    fn expired_cert() {
        // Cert expired at t=5 when current time is t=6.
        let cert = generate_cert(1, 5);
        set_time(6);
        let lifetime = Lifetime::from_cert(&cert);

        assert_eq!(Lifetime::Expired, lifetime);
        assert!(lifetime.should_renew(100.0));
    }

    #[test]
    #[serial_test::serial]
    fn valid_cert() {
        // Cert at 50% lifetime.
        let cert = generate_cert(-2, 2);
        set_time(0);
        let lifetime = Lifetime::from_cert(&cert);

        assert_eq!(Lifetime::Valid(0.5), lifetime);
        assert!(lifetime.should_renew(0.4));
        assert!(lifetime.should_renew(0.5));
        assert!(!lifetime.should_renew(0.6));
    }
}
