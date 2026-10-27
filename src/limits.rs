//! Rate limits and the other in-memory state of the relay.
//!
//! Everything here lives in memory and is lost on restart, on purpose
//! (docs/design.md section 9). Token buckets are kept per scope (per instance,
//! per handle, per device, per address) and never per pair, so the relay has no
//! table that connects an instance to a device.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

use serde::Deserialize;

use crate::clock::Clock;

/// Every number the design lists in section 10, with the design's values as
/// the defaults. Override any of them with a JSON file (`PP_LIMITS_FILE`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Leading zero bits a registration proof of work needs.
    pub pow_difficulty: u32,
    /// Seconds a challenge stays valid.
    pub challenge_ttl_secs: i64,
    /// Instance registrations per address per day.
    pub instance_reg_per_addr_day: u32,
    /// Instance registrations per day in total; above it `503` until tomorrow.
    pub instance_reg_per_day: u32,
    pub device_reg_per_addr_hour: u32,
    pub device_reg_per_addr_day: u32,
    /// Hard cap on device rows.
    pub max_devices: u32,
    pub handle_create_per_device_hour: u32,
    pub max_handles_per_device: u32,
    /// Token updates (`PUT /v1/devices/{id}`) per device per hour.
    pub device_update_per_hour: u32,
    pub alert_per_handle_hour: u32,
    pub alert_handle_burst: u32,
    pub sync_per_handle_hour: u32,
    pub sync_handle_burst: u32,
    pub alert_per_device_hour: u32,
    pub sync_per_device_hour: u32,
    /// Sends per hour for the "new" tier.
    pub send_per_instance_hour_new: u32,
    /// Sends per hour for the "established" tier.
    pub send_per_instance_hour_established: u32,
    /// Days without limit hits or suspensions before "new" becomes "established".
    pub established_after_days: i64,
    /// Unknown-handle answers per instance per hour before the instance gets `429`.
    pub unknown_handles_per_instance_hour: u32,
    /// `429`s in one day after which an instance is suspended automatically.
    pub auto_suspend_throttled_per_day: u32,
    /// Sends per second toward Apple, per app (the circuit breaker's ceiling).
    pub app_sends_per_second: u32,
    /// Wrong credentials per address per hour before that address gets `429`.
    pub auth_failures_per_addr_hour: u32,
    /// Handles in one push request.
    pub max_handles_per_request: usize,
    /// Keys a rate limiter tracks at most.
    pub max_tracked_keys: usize,
    /// Requests handled at once; more are shed with `503`.
    pub max_inflight_requests: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            pow_difficulty: 20,
            challenge_ttl_secs: 300,
            instance_reg_per_addr_day: 5,
            instance_reg_per_day: 200,
            device_reg_per_addr_hour: 20,
            device_reg_per_addr_day: 100,
            max_devices: 1_000_000,
            handle_create_per_device_hour: 10,
            max_handles_per_device: 32,
            device_update_per_hour: 20,
            alert_per_handle_hour: 6,
            alert_handle_burst: 3,
            sync_per_handle_hour: 30,
            sync_handle_burst: 5,
            alert_per_device_hour: 30,
            sync_per_device_hour: 120,
            send_per_instance_hour_new: 600,
            send_per_instance_hour_established: 6000,
            established_after_days: 7,
            unknown_handles_per_instance_hour: 20,
            auto_suspend_throttled_per_day: 1000,
            app_sends_per_second: 100,
            auth_failures_per_addr_hour: 60,
            max_handles_per_request: 25,
            max_tracked_keys: 100_000,
            max_inflight_requests: 2048,
        }
    }
}

impl Limits {
    /// Rejects values that would make the relay misbehave.
    pub fn validate(&self) -> Result<(), String> {
        if self.pow_difficulty > 40 {
            return Err("pow_difficulty above 40 is not solvable".into());
        }
        if self.max_handles_per_request == 0 || self.max_handles_per_request > 100 {
            return Err("max_handles_per_request must be 1 to 100".into());
        }
        if self.challenge_ttl_secs < 10 {
            return Err("challenge_ttl_secs must be at least 10".into());
        }
        Ok(())
    }
}

struct Bucket {
    tokens: f64,
    last_ms: i64,
}

/// A set of token buckets, one per key, bounded in size.
pub struct Limiter {
    clock: Clock,
    burst: f64,
    refill_per_ms: f64,
    max_keys: usize,
    map: Mutex<HashMap<String, Bucket>>,
}

impl Limiter {
    /// `per` tokens every `window_secs`, up to `burst` at once.
    pub fn new(clock: &Clock, burst: u32, per: u32, window_secs: u32, max_keys: usize) -> Self {
        Limiter {
            clock: clock.clone(),
            burst: f64::from(burst.max(1)),
            refill_per_ms: f64::from(per) / (f64::from(window_secs) * 1000.0),
            max_keys: max_keys.max(16),
            map: Mutex::new(HashMap::new()),
        }
    }

    /// `per` per hour, `burst` at once.
    pub fn per_hour(clock: &Clock, burst: u32, per: u32, max_keys: usize) -> Self {
        Self::new(clock, burst, per, 3600, max_keys)
    }

    /// `per` per day, all of it at once.
    pub fn per_day(clock: &Clock, per: u32, max_keys: usize) -> Self {
        Self::new(clock, per, per, 86_400, max_keys)
    }

    fn refill(&self, b: &mut Bucket, now: i64) {
        let elapsed = (now - b.last_ms).max(0) as f64;
        b.tokens = (b.tokens + elapsed * self.refill_per_ms).min(self.burst);
        b.last_ms = now;
    }

    fn retry_after(&self, tokens: f64, need: f64) -> u64 {
        if self.refill_per_ms <= 0.0 {
            return 3600;
        }
        let ms = (need - tokens) / self.refill_per_ms;
        ((ms / 1000.0).ceil() as u64).max(1)
    }

    /// Takes one token; `Err(seconds)` says when to retry.
    pub fn take(&self, key: &str) -> Result<(), u64> {
        self.take_n(key, 1)
    }

    /// Takes `n` tokens at once or none.
    pub fn take_n(&self, key: &str, n: u32) -> Result<(), u64> {
        let now = self.clock.now_ms();
        let need = f64::from(n);
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(key) && map.len() >= self.max_keys {
            self.make_room(&mut map, now);
        }
        let b = map.entry(key.to_string()).or_insert(Bucket {
            tokens: self.burst,
            last_ms: now,
        });
        self.refill(b, now);
        if b.tokens >= need {
            b.tokens -= need;
            Ok(())
        } else {
            Err(self.retry_after(b.tokens, need))
        }
    }

    /// Whether `n` tokens are there, without taking them.
    pub fn has(&self, key: &str, n: u32) -> Result<(), u64> {
        let now = self.clock.now_ms();
        let need = f64::from(n);
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match map.get_mut(key) {
            None => Ok(()),
            Some(b) => {
                self.refill(b, now);
                if b.tokens >= need {
                    Ok(())
                } else {
                    Err(self.retry_after(b.tokens, need))
                }
            }
        }
    }

    /// Frees room for a new key: drops buckets that are full again (they carry
    /// no information), and if that is not enough, forgets everything.
    fn make_room(&self, map: &mut HashMap<String, Bucket>, now: i64) {
        map.retain(|_, b| {
            let elapsed = (now - b.last_ms).max(0) as f64;
            b.tokens + elapsed * self.refill_per_ms < self.burst
        });
        if map.len() >= self.max_keys {
            map.clear();
        }
    }

    /// Drops buckets that are full again.
    pub fn prune(&self) {
        let now = self.clock.now_ms();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, b| {
            let elapsed = (now - b.last_ms).max(0) as f64;
            b.tokens + elapsed * self.refill_per_ms < self.burst
        });
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A bounded set of keys that expire, such as used challenges and handled
/// events.
pub struct TimedSet<K> {
    clock: Clock,
    ttl_ms: i64,
    max: usize,
    map: Mutex<HashMap<K, i64>>,
}

/// The set is full of live entries.
#[derive(Debug, PartialEq, Eq)]
pub struct Full;

impl<K: Hash + Eq> TimedSet<K> {
    pub fn new(clock: &Clock, ttl_secs: i64, max: usize) -> Self {
        TimedSet {
            clock: clock.clone(),
            ttl_ms: ttl_secs * 1000,
            max,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn contains(&self, key: &K) -> bool {
        let now = self.clock.now_ms();
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).is_some_and(|exp| *exp > now)
    }

    /// Adds `key`: `Ok(true)` if it is new, `Ok(false)` if it was there.
    pub fn insert(&self, key: K) -> Result<bool, Full> {
        let now = self.clock.now_ms();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(exp) = map.get(&key)
            && *exp > now
        {
            return Ok(false);
        }
        if map.len() >= self.max {
            map.retain(|_, exp| *exp > now);
            if map.len() >= self.max {
                return Err(Full);
            }
        }
        map.insert(key, now + self.ttl_ms);
        Ok(true)
    }

    /// Drops expired entries.
    pub fn prune(&self) {
        let now = self.clock.now_ms();
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, exp| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_bursts_then_refills() {
        let clock = Clock::new();
        let l = Limiter::per_hour(&clock, 3, 6, 100);
        for _ in 0..3 {
            assert!(l.take("k").is_ok());
        }
        let wait = l.take("k").unwrap_err();
        assert!((1..=600).contains(&wait), "{wait}");
        // Six per hour is one every ten minutes.
        clock.advance_secs(601);
        assert!(l.take("k").is_ok());
        assert!(l.take("k").is_err());
        // Other keys are independent.
        assert!(l.take("other").is_ok());
    }

    #[test]
    fn peek_does_not_take() {
        let clock = Clock::new();
        let l = Limiter::per_hour(&clock, 2, 2, 100);
        assert!(l.has("k", 2).is_ok());
        assert!(l.has("k", 2).is_ok());
        assert!(l.take_n("k", 2).is_ok());
        assert!(l.has("k", 1).is_err());
    }

    #[test]
    fn keys_are_bounded() {
        let clock = Clock::new();
        let l = Limiter::per_hour(&clock, 1, 1, 16);
        for i in 0..200 {
            let _ = l.take(&format!("k{i}"));
        }
        assert!(l.len() <= 16);
    }

    #[test]
    fn timed_set_expires_and_is_bounded() {
        let clock = Clock::new();
        let s: TimedSet<u32> = TimedSet::new(&clock, 10, 2);
        assert_eq!(s.insert(1), Ok(true));
        assert_eq!(s.insert(1), Ok(false));
        assert_eq!(s.insert(2), Ok(true));
        assert_eq!(s.insert(3), Err(Full));
        clock.advance_secs(11);
        assert!(!s.contains(&1));
        assert_eq!(s.insert(3), Ok(true));
    }

    #[test]
    fn default_limits_are_valid() {
        assert!(Limits::default().validate().is_ok());
        let bad = Limits {
            pow_difficulty: 99,
            ..Limits::default()
        };
        assert!(bad.validate().is_err());
    }
}
