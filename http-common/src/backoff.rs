// Copyright (c) Microsoft. All rights reserved.

use std::time::Duration;

use rand::Rng;

pub const DEFAULT_BACKOFF: Backoff<4> = Backoff {
    pattern: [
        BackoffInstance::new(Duration::from_secs(60), Duration::from_secs(10)),
        BackoffInstance::new(Duration::from_secs(120), Duration::from_secs(20)),
        BackoffInstance::new(Duration::from_secs(180), Duration::from_secs(30)),
        BackoffInstance::new(Duration::from_secs(300), Duration::from_secs(30)),
    ],
};

pub struct Backoff<const N: usize> {
    pattern: [BackoffInstance; N],
}

impl<const N: usize> Backoff<N> {
    #[allow(clippy::unused_self, clippy::cast_possible_truncation)]
    pub fn max_retries(&self) -> u32 {
        N as u32
    }

    /// Computes backoff for current try. Returns None if no retry attempts left
    pub fn get_backoff_duration(&self, current_attempt: u32) -> Option<Duration> {
        self.pattern
            .get(current_attempt as usize - 1)
            .map(BackoffInstance::backoff_duration)
    }
}

pub struct BackoffInstance {
    duration: Duration,
    max_jitter: Duration,
}

impl BackoffInstance {
    const fn new(duration: Duration, max_jitter: Duration) -> Self {
        Self {
            duration,
            max_jitter,
        }
    }

    fn backoff_duration(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter_multiple = rng.gen_range(0.0..1.0);

        self.duration + self.max_jitter.mul_f32(jitter_multiple)
    }
}
