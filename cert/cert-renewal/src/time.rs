// Copyright (c) Microsoft. All rights reserved.

/// Time is represented as seconds since the UNIX epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Time(i64);

/// Logs a message and aborts the process. This function is called if the process encounters
/// a fatal clock error.
fn abort(message: impl std::fmt::Display) -> ! {
    log::error!("{}", message);

    std::process::abort();
}

impl Time {
    /// Get current time.
    #[cfg(not(test))]
    pub fn now() -> Self {
        if let Ok(now) = openssl::asn1::Asn1Time::days_from_now(0) {
            now.as_ref().into()
        } else {
            abort("Failed to read current time.");
        }
    }

    /// When testing, allow current time to be set by test functions.
    #[cfg(test)]
    pub fn now() -> Self {
        let now = test_time::NOW.load(std::sync::atomic::Ordering::Acquire);

        Time(now)
    }

    /// A time that, for all intents and purposes, never elapses.
    pub fn forever() -> Self {
        Time(i64::MAX)
    }

    /// Check whether this time is in the past.
    pub fn in_past(self) -> bool {
        Time::now() >= self
    }

    /// Sleep until this time elapses. Returns immediately for past times.
    pub fn sleep_until(self) -> tokio::time::Sleep {
        // The calculation of deadline overflows for i64::MAX. Sleep for Duration::MAX
        // if the requested sleep time is "forever".
        if self == Time::forever() {
            return tokio::time::sleep(tokio::time::Duration::MAX);
        }

        let now = Time::now();
        let diff = self - now;

        if diff <= 0 {
            // Return immediately for past times.
            tokio::time::sleep_until(tokio::time::Instant::now())
        } else {
            // Converting a positive i64 to u64 should never fail.
            let diff = u64::try_from(diff).unwrap();

            let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(diff);
            tokio::time::sleep_until(deadline)
        }
    }
}

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self == &Time::forever() {
            write!(f, "the end of time")
        } else {
            let date_time = chrono::NaiveDateTime::from_timestamp(self.0, 0);
            let date_time = chrono::DateTime::<chrono::Utc>::from_utc(date_time, chrono::Utc);

            write!(f, "{}", date_time.to_rfc3339())
        }
    }
}

impl std::convert::From<i64> for Time {
    fn from(time: i64) -> Self {
        Time(time)
    }
}

impl std::convert::From<&openssl::asn1::Asn1TimeRef> for Time {
    fn from(time: &openssl::asn1::Asn1TimeRef) -> Self {
        let epoch = if let Ok(epoch) = openssl::asn1::Asn1Time::from_unix(0) {
            epoch
        } else {
            abort("Failed to determine UNIX epoch.");
        };

        let unix = if let Ok(diff) = epoch.diff(time) {
            diff
        } else {
            abort("Failed to calculate time difference.");
        };

        let unix = i64::from(unix.days) * 86400 + i64::from(unix.secs);

        Time(unix)
    }
}

impl std::ops::Add<i64> for Time {
    type Output = Self;

    fn add(self, other: i64) -> Self::Output {
        Time(self.0 + other)
    }
}

impl std::ops::Sub for Time {
    type Output = i64;

    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}

impl std::ops::Sub<i64> for Time {
    type Output = Self;

    fn sub(self, other: i64) -> Self::Output {
        Time(self.0 - other)
    }
}

// Allow time to be set when testing. All tests that use these functions or call
// `Time::now` must be serialized to prevent them from interfering with each other.
// Tests should also call `reset` during setup so that they start with a known time.
#[cfg(test)]
pub(crate) mod test_time {
    use std::sync::atomic::{AtomicI64, Ordering};

    pub(super) static NOW: AtomicI64 = AtomicI64::new(0);

    pub(crate) fn set(time: i64) {
        NOW.store(time, Ordering::Release);
    }

    pub(crate) fn reset() {
        NOW.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::Time;

    use tokio::time::{Duration, Instant};

    #[test]
    fn time_display() {
        assert_eq!("1970-01-01T00:00:00+00:00", Time::from(0).to_string());
        assert_eq!(
            "1938-04-24T22:13:20+00:00",
            Time::from(-1_000_000_000).to_string()
        );
        assert_eq!(
            "2001-09-09T01:46:40+00:00",
            Time::from(1_000_000_000).to_string()
        );
        assert_eq!("the end of time", Time::forever().to_string());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sleep_until() {
        crate::test_time::reset();

        // Time in past. Should return immediately.
        let time = Time::from(-1);
        let start = Instant::now();
        time.sleep_until().await;
        assert!(start.elapsed() < Duration::from_secs(1));

        // Sleep for 1 second.
        let time = Time::from(1);
        let start = Instant::now();
        time.sleep_until().await;
        let elapsed = start.elapsed();
        assert!(elapsed > Duration::from_millis(500) && elapsed < Duration::from_millis(1500));

        // Test the calculation of sleeping "forever".
        let time = Time::forever();
        let forever = time.sleep_until();
        assert!(!forever.is_elapsed());
    }
}
