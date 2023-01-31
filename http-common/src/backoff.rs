// Copyright (c) Microsoft. All rights reserved.

use std::time::Duration;

use rand::Rng;

pub const DEFAULT_BACKOFF: Backoff<4> = Backoff {
    pattern: [
        BackoffInstance::from_secs(60, 10),
        BackoffInstance::from_secs(120, 20),
        BackoffInstance::from_secs(180, 30),
        BackoffInstance::from_secs(300, 30),
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
    const fn from_secs(duration: u64, max_jitter: u64) -> Self {
        Self {
            duration: Duration::from_secs(duration),
            max_jitter: Duration::from_secs(max_jitter),
        }
    }

    fn backoff_duration(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter_multiple = rng.gen_range(0.0..1.0);

        self.duration + self.max_jitter.mul_f32(jitter_multiple)
    }
}
