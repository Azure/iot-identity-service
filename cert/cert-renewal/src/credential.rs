// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

/// Priority queue for credentials to renew. The standard library heap is a max-heap,
/// so this structure stores every `Credential` in a `Reverse` for a min-heap.
#[derive(Debug)]
pub(crate) struct CredentialHeap {
    heap: std::collections::BinaryHeap<core::cmp::Reverse<Credential>>,
}

impl CredentialHeap {
    /// Create new `CredentialHeap`.
    pub fn new() -> Self {
        CredentialHeap {
            heap: std::collections::BinaryHeap::new(),
        }
    }

    /// Add a new credential. Return value indicates whether the renewal timer should
    /// be rescheduled.
    pub fn push(&mut self, credential: Credential) -> Option<crate::Time> {
        let new_expiry = credential.next_renewal;
        let credential = std::cmp::Reverse(credential);

        if let Some(first) = self.peek() {
            let prev_expiry = first.next_renewal;

            self.heap.push(credential);

            // The renewal timer must be rescheduled if the soonest-expiring element changed.
            if prev_expiry == new_expiry {
                None
            } else {
                Some(new_expiry)
            }
        } else {
            self.heap.push(credential);

            Some(new_expiry)
        }
    }

    /// Peek the soonest-expiring credential.
    pub fn peek(&self) -> Option<&Credential> {
        if let Some(credential) = self.heap.peek() {
            Some(&credential.0)
        } else {
            None
        }
    }

    /// Remove the soonest-expiring credential.
    pub fn pop(&mut self) -> Option<Credential> {
        if let Some(credential) = self.heap.pop() {
            Some(credential.0)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) struct Credential {
    pub(crate) next_renewal: crate::Time,
    pub(crate) cert_id: String,
    pub(crate) digest: Vec<u8>,
    pub(crate) key_id: String,
    pub(crate) retry_period: i64,
    pub(crate) policy: crate::RenewalPolicy,
}

impl std::cmp::Ord for Credential {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.next_renewal.cmp(&other.next_renewal)
    }
}

impl std::cmp::PartialOrd for Credential {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        self.next_renewal == other.next_renewal
    }
}

impl std::cmp::Eq for Credential {}

impl Credential {
    /// Create a new `Credential`. The provided `cert_pem` and `cert_id` should be a valid,
    /// unexpired certificate that is not within its renewal threshold.
    pub fn new(
        cert_id: &str,
        cert: &openssl::x509::X509,
        key_id: &str,
        policy: crate::RenewalPolicy,
    ) -> Result<Self, Error> {
        let (next_renewal, retry_period) = renewal_times(cert, &policy)?;

        let digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
            .to_vec();

        Ok(Credential {
            next_renewal,
            cert_id: cert_id.to_string(),
            digest,
            key_id: key_id.to_string(),
            retry_period,
            policy,
        })
    }

    /// Recalculate renewal times and thumbprints based on the given cert.
    pub fn reset(mut self, cert: &openssl::x509::X509) -> Result<Self, Error> {
        let digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
            .to_vec();

        let (next_renewal, retry_period) = renewal_times(cert, &self.policy)?;

        self.next_renewal = next_renewal;
        self.digest = digest;
        self.retry_period = retry_period;

        Ok(self)
    }
}

fn renewal_times(
    cert: &openssl::x509::X509,
    policy: &crate::RenewalPolicy,
) -> Result<(crate::Time, i64), Error> {
    let not_before = crate::Time::from(cert.not_before());
    let not_after = crate::Time::from(cert.not_after());

    if not_before >= not_after {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "cert not_before is not before not_after",
        ));
    }

    if not_after.in_past() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "cannot calculate initial renewal time for expired cert",
        ));
    }

    // Calculate the intial renewal time.
    let initial_renewal = match policy.threshold {
        crate::Policy::Percentage(threshold) => {
            let total_lifetime = not_after - not_before;
            let threshold = total_lifetime - total_lifetime * threshold / 100;

            not_after - threshold
        }

        crate::Policy::Time(threshold) => not_after - threshold,
    };

    // Calculate renewal retry period.
    let retry_period = match policy.retry {
        crate::Policy::Percentage(retry) => {
            let total_lifetime = not_after - not_before;

            total_lifetime * retry / 100
        }

        crate::Policy::Time(retry) => retry,
    };

    // Require the retry period to be at least 1 second.
    let retry_period = std::cmp::max(retry_period, 1);

    if initial_renewal.in_past() {
        Err(Error::new(
            ErrorKind::InvalidInput,
            "cannot calculate initial renewal time for cert that should be renewed",
        ))
    } else {
        Ok((initial_renewal, retry_period))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_cert;

    use super::renewal_times;
    use super::{Credential, CredentialHeap};

    #[test]
    fn calculate_renewal_times() {
        // Bad cert: not_after is before not_before.
        let cert = test_cert(5, 1);
        renewal_times(
            &cert,
            &crate::RenewalPolicy {
                threshold: crate::Policy::Percentage(80),
                retry: crate::Policy::Percentage(4),
            },
        )
        .unwrap_err();

        // This function should not be called for expired certs.
        let cert = test_cert(-10, -5);
        renewal_times(
            &cert,
            &crate::RenewalPolicy {
                threshold: crate::Policy::Percentage(50),
                retry: crate::Policy::Percentage(4),
            },
        )
        .unwrap_err();

        // This function should not be called for certs that should be renewed.
        let cert = test_cert(-3, 1);
        renewal_times(
            &cert,
            &crate::RenewalPolicy {
                threshold: crate::Policy::Percentage(50),
                retry: crate::Policy::Percentage(4),
            },
        )
        .unwrap_err();

        // Check initial renewal calculation.
        let cert = test_cert(-5, 5);
        assert_eq!(
            (crate::Time::from(1), 2),
            renewal_times(
                &cert,
                &crate::RenewalPolicy {
                    threshold: crate::Policy::Percentage(60),
                    retry: crate::Policy::Percentage(20),
                }
            )
            .unwrap()
        );
        assert_eq!(
            (crate::Time::from(4), 1),
            renewal_times(
                &cert,
                &crate::RenewalPolicy {
                    threshold: crate::Policy::Time(1),
                    retry: crate::Policy::Time(1),
                }
            )
            .unwrap()
        );
    }

    #[test]
    fn new_credential() {
        let policy = crate::RenewalPolicy {
            threshold: crate::Policy::Percentage(80),
            retry: crate::Policy::Percentage(4),
        };

        let cert = test_cert(-5, 5);

        let digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec();

        let credential = Credential::new("test-cert", &cert, "test-key", policy.clone()).unwrap();

        // PartialEq for Credential only compares next_renewal, so fields must be compared manually.
        assert_eq!(crate::Time::from(3), credential.next_renewal);
        assert_eq!("test-cert", &credential.cert_id);
        assert_eq!(digest, credential.digest);
        assert_eq!("test-key", &credential.key_id);
        assert_eq!(1, credential.retry_period);
        assert_eq!(policy, credential.policy);
    }

    #[test]
    fn reset_credential() {
        let policy = crate::RenewalPolicy {
            threshold: crate::Policy::Percentage(80),
            retry: crate::Policy::Percentage(4),
        };

        let old_cert = test_cert(-50, 50);
        let digest = old_cert
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec();

        let credential =
            Credential::new("test-cert", &old_cert, "test-key", policy.clone()).unwrap();
        assert_eq!(crate::Time::from(30), credential.next_renewal);
        assert_eq!("test-cert", &credential.cert_id);
        assert_eq!(digest, credential.digest);
        assert_eq!("test-key", &credential.key_id);
        assert_eq!(4, credential.retry_period);
        assert_eq!(policy, credential.policy);

        let new_cert = test_cert(-20, 180);
        let digest = new_cert
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .to_vec();

        let credential = credential.reset(&new_cert).unwrap();
        assert_eq!(crate::Time::from(140), credential.next_renewal);
        assert_eq!("test-cert", &credential.cert_id);
        assert_eq!(digest, credential.digest);
        assert_eq!("test-key", &credential.key_id);
        assert_eq!(8, credential.retry_period);
        assert_eq!(policy, credential.policy);
    }

    #[test]
    fn credential_heap() {
        let policy = crate::RenewalPolicy {
            threshold: crate::Policy::Percentage(80),
            retry: crate::Policy::Percentage(4),
        };

        let cert_1 = test_cert(-1, 10);
        let cert_1 = Credential::new("cert_1", &cert_1, "cert_key_1", policy.clone()).unwrap();

        let cert_2 = test_cert(-3, 5);
        let cert_2 = Credential::new("cert_2", &cert_2, "cert_key_2", policy.clone()).unwrap();

        let cert_3 = test_cert(-5, 8);
        let cert_3 = Credential::new("cert_3", &cert_3, "cert_key_3", policy.clone()).unwrap();

        let mut heap = CredentialHeap::new();
        assert!(heap.peek().is_none());
        assert!(heap.pop().is_none());

        heap.push(cert_1);
        heap.push(cert_2);
        heap.push(cert_3);

        let cert = heap.pop().unwrap();
        assert_eq!("cert_2", cert.cert_id);

        let cert = heap.pop().unwrap();
        assert_eq!("cert_3", cert.cert_id);

        let cert = heap.pop().unwrap();
        assert_eq!("cert_1", cert.cert_id);
    }
}
