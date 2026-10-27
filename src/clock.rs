//! The relay's clock. Wall time plus an offset that only tests move, so rules
//! that depend on hours and days can be tested without waiting.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::day_of;

#[derive(Debug, Clone, Default)]
pub struct Clock {
    offset_ms: Arc<AtomicI64>,
}

impl Clock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> i64 {
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        real + self.offset_ms.load(Ordering::Relaxed)
    }

    /// Seconds since the Unix epoch.
    pub fn now_secs(&self) -> i64 {
        self.now_ms().div_euclid(1000)
    }

    /// Today's day number (days since 1970-01-01, UTC).
    pub fn today(&self) -> i64 {
        day_of(self.now_secs())
    }

    /// Moves the clock forward. For tests.
    pub fn advance_secs(&self, secs: i64) {
        self.offset_ms.fetch_add(secs * 1000, Ordering::Relaxed);
    }
}
