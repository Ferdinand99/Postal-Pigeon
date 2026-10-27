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
    /// Instance registrations per day from one network (the IPv4 /24 or IPv6 /48).
    pub instance_reg_per_prefix_day: u32,
    /// Registrations in the last hour above which the proof of work gets harder,
    /// one more bit for every doubling.
    pub pow_adaptive_threshold_per_hour: u32,
    /// Most extra bits the adaptive proof of work adds.
    pub pow_adaptive_max_extra_bits: u32,
    pub device_reg_per_addr_hour: u32,
    pub device_reg_per_addr_day: u32,
    /// Device registrations per hour and per day from one network (IPv4 /24, IPv6 /48).
    pub device_reg_per_prefix_hour: u32,
    pub device_reg_per_prefix_day: u32,
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
    /// Extra permits only /healthz uses, so it answers while the rest is shed.
    pub health_inflight_requests: usize,
    /// Connections open at once; more wait in the kernel backlog.
    pub max_connections: usize,
    /// Seconds a client has to send its request headers, also the idle time of
    /// a kept-alive connection.
    pub header_read_timeout_secs: u64,
    /// Sends per hour for a device that has never had a push accepted.
    pub unverified_device_per_hour: u32,
    /// Distinct devices answering `BadDeviceToken` (or another strike-worthy
    /// answer) within the window that stop all striking and deleting.
    pub strike_trip_devices: u32,
    /// And the share of an app's answers in the window that they must be, in percent.
    pub strike_trip_percent: u32,
    /// Length of that window in seconds.
    pub strike_window_secs: i64,
    /// How long striking stays off once tripped, in seconds.
    pub strike_trip_secs: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            pow_difficulty: 20,
            challenge_ttl_secs: 300,
            instance_reg_per_addr_day: 5,
            // A safety cap only; the per-address and per-network limits and
            // the adaptive proof of work do the real work.
            instance_reg_per_day: 5000,
            instance_reg_per_prefix_day: 25,
            pow_adaptive_threshold_per_hour: 30,
            pow_adaptive_max_extra_bits: 8,
            device_reg_per_addr_hour: 20,
            device_reg_per_addr_day: 100,
            device_reg_per_prefix_hour: 100,
            device_reg_per_prefix_day: 500,
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
            health_inflight_requests: 16,
            max_connections: 4096,
            header_read_timeout_secs: 10,
            unverified_device_per_hour: 3,
            strike_trip_devices: 10,
            strike_trip_percent: 50,
            strike_window_secs: 600,
            strike_trip_secs: 3600,
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
        if self.pow_difficulty + self.pow_adaptive_max_extra_bits > 40 {
            return Err(
                "pow_difficulty plus pow_adaptive_max_extra_bits above 40 is not solvable".into(),
            );
        }
        if self.strike_trip_percent > 100 || self.strike_trip_devices == 0 {
            return Err(
                "strike_trip_percent is 0 to 100 and strike_trip_devices at least 1".into(),
            );
        }
        Ok(())
    }

    /// The proof-of-work difficulty to ask for when `recent` instances
    /// registered in the last hour: the base, plus one bit for every doubling
    /// above the threshold, up to the configured maximum.
    pub fn difficulty_for(&self, recent: u32) -> u32 {
        let threshold = self.pow_adaptive_threshold_per_hour.max(1);
        let mut extra = 0;
        let mut level = u64::from(threshold);
        while u64::from(recent) >= level && extra < self.pow_adaptive_max_extra_bits {
            extra += 1;
            level *= 2;
        }
        self.pow_difficulty + extra
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
    /// no information), and if that is not enough, evicts the least recently
    /// used tenth, so a flood of new keys can't wipe everybody's history.
    fn make_room(&self, map: &mut HashMap<String, Bucket>, now: i64) {
        map.retain(|_, b| {
            let elapsed = (now - b.last_ms).max(0) as f64;
            b.tokens + elapsed * self.refill_per_ms < self.burst
        });
        if map.len() >= self.max_keys {
            let mut by_age: Vec<(i64, String)> =
                map.iter().map(|(k, b)| (b.last_ms, k.clone())).collect();
            by_age.sort_unstable();
            let drop = (self.max_keys / 10).max(1);
            for (_, k) in by_age.into_iter().take(drop) {
                map.remove(&k);
            }
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

    /// Forgets `key`.
    pub fn remove(&self, key: &K) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
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

impl<K: Hash + Eq + Clone> TimedSet<K> {
    /// Adds `key` like [`TimedSet::insert`] and returns whether it is new, but
    /// when the set is full of live entries it forgets the oldest one instead
    /// of refusing, so the set never silently stops working.
    pub fn insert_evicting(&self, key: K) -> bool {
        let now = self.clock.now_ms();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&key).is_some_and(|exp| *exp > now) {
            return false;
        }
        if map.len() >= self.max {
            map.retain(|_, exp| *exp > now);
            if map.len() >= self.max {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, exp)| **exp)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(key, now + self.ttl_ms);
        true
    }
}

/// Counts events over the last hour, in one-minute steps.
pub struct RecentCounter {
    clock: Clock,
    slots: Mutex<[(i64, u32); 60]>,
}

impl RecentCounter {
    pub fn new(clock: &Clock) -> Self {
        RecentCounter {
            clock: clock.clone(),
            slots: Mutex::new([(i64::MIN, 0); 60]),
        }
    }

    pub fn record(&self) {
        let minute = self.clock.now_secs().div_euclid(60);
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = &mut slots[minute.rem_euclid(60) as usize];
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }

    /// Events in the last 60 minutes.
    pub fn last_hour(&self) -> u32 {
        let minute = self.clock.now_secs().div_euclid(60);
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .iter()
            .filter(|(m, _)| *m > minute - 60 && *m <= minute)
            .map(|(_, n)| *n)
            .fold(0u32, u32::saturating_add)
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
    fn full_limiter_evicts_the_least_recently_used_not_everything() {
        let clock = Clock::new();
        let l = Limiter::per_hour(&clock, 2, 2, 20);
        // One heavy user, spending its budget, then a flood of other keys.
        assert!(l.take("heavy").is_ok());
        assert!(l.take("heavy").is_ok());
        assert!(l.take("heavy").is_err());
        for i in 0..40 {
            clock.advance_secs(1);
            let _ = l.take(&format!("flood{i}"));
        }
        assert!(l.len() <= 20);
        // The flood used the newest keys; the heavy user was the oldest, so it
        // may be forgotten, but the newest flood keys are all still there.
        assert!(l.has("flood39", 1).is_ok());
        assert!(l.take("flood39").is_ok());

        assert!(
            l.take("flood39").is_err(),
            "recent history survives eviction"
        );
    }

    #[test]
    fn evicting_set_never_stops_working() {
        let clock = Clock::new();
        let s: TimedSet<u32> = TimedSet::new(&clock, 100, 3);
        for i in 0..3 {
            assert!(s.insert_evicting(i));
            clock.advance_secs(1);
        }
        assert!(!s.insert_evicting(2), "a live entry is a duplicate");
        assert!(s.insert_evicting(10), "full: the oldest goes");
        assert!(!s.contains(&0) && s.contains(&1) && s.contains(&10));
        s.remove(&10);
        assert!(!s.contains(&10));
    }

    #[test]
    fn recent_counter_counts_the_last_hour() {
        let clock = Clock::new();
        let c = RecentCounter::new(&clock);
        for _ in 0..5 {
            c.record();
        }
        assert_eq!(c.last_hour(), 5);
        clock.advance_secs(30 * 60);
        c.record();
        assert_eq!(c.last_hour(), 6);
        clock.advance_secs(31 * 60);
        assert_eq!(c.last_hour(), 1, "the first five are older than an hour");
        clock.advance_secs(3600);
        assert_eq!(c.last_hour(), 0);
    }

    #[test]
    fn difficulty_rises_with_volume_up_to_a_cap() {
        let l = Limits {
            pow_difficulty: 20,
            pow_adaptive_threshold_per_hour: 30,
            pow_adaptive_max_extra_bits: 3,
            ..Limits::default()
        };
        assert_eq!(l.difficulty_for(0), 20);
        assert_eq!(l.difficulty_for(29), 20);
        assert_eq!(l.difficulty_for(30), 21);
        assert_eq!(l.difficulty_for(59), 21);
        assert_eq!(l.difficulty_for(60), 22);
        assert_eq!(l.difficulty_for(120), 23);
        assert_eq!(l.difficulty_for(1_000_000), 23, "capped");
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
