//! Shared application state.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::apns::Apns;
use crate::clock::Clock;
use crate::config::Settings;
use crate::crypto::Keys;
use crate::db::Db;
use crate::limits::{Limiter, Limits, TimedSet};

/// How long a handled `event_id` is remembered (seconds).
pub const EVENT_TTL_SECS: i64 = 15 * 60;

/// All the token buckets. Each is keyed by one scope only (an address, an
/// instance, a handle, a device or an app), never by a pair.
pub struct Limiters {
    pub instance_reg_addr: Limiter,
    pub device_reg_addr_hour: Limiter,
    pub device_reg_addr_day: Limiter,
    pub handle_create: Limiter,
    pub device_update: Limiter,
    pub alert_handle: Limiter,
    pub sync_handle: Limiter,
    pub alert_device: Limiter,
    pub sync_device: Limiter,
    pub instance_new: Limiter,
    pub instance_established: Limiter,
    pub unknown_handles: Limiter,
    pub auth_failures: Limiter,
    pub app_sends: Limiter,
}

impl Limiters {
    pub fn new(clock: &Clock, l: &Limits) -> Self {
        let k = l.max_tracked_keys;
        Limiters {
            instance_reg_addr: Limiter::per_day(clock, l.instance_reg_per_addr_day, k),
            device_reg_addr_hour: Limiter::per_hour(
                clock,
                l.device_reg_per_addr_hour,
                l.device_reg_per_addr_hour,
                k,
            ),
            device_reg_addr_day: Limiter::per_day(clock, l.device_reg_per_addr_day, k),
            handle_create: Limiter::per_hour(
                clock,
                l.handle_create_per_device_hour,
                l.handle_create_per_device_hour,
                k,
            ),
            device_update: Limiter::per_hour(
                clock,
                l.device_update_per_hour,
                l.device_update_per_hour,
                k,
            ),
            alert_handle: Limiter::per_hour(
                clock,
                l.alert_handle_burst,
                l.alert_per_handle_hour,
                k,
            ),
            sync_handle: Limiter::per_hour(clock, l.sync_handle_burst, l.sync_per_handle_hour, k),
            alert_device: Limiter::per_hour(
                clock,
                l.alert_per_device_hour,
                l.alert_per_device_hour,
                k,
            ),
            sync_device: Limiter::per_hour(
                clock,
                l.sync_per_device_hour,
                l.sync_per_device_hour,
                k,
            ),
            instance_new: Limiter::per_hour(
                clock,
                l.send_per_instance_hour_new,
                l.send_per_instance_hour_new,
                k,
            ),
            instance_established: Limiter::per_hour(
                clock,
                l.send_per_instance_hour_established,
                l.send_per_instance_hour_established,
                k,
            ),
            unknown_handles: Limiter::per_hour(
                clock,
                l.unknown_handles_per_instance_hour,
                l.unknown_handles_per_instance_hour,
                k,
            ),
            auth_failures: Limiter::per_hour(
                clock,
                l.auth_failures_per_addr_hour,
                l.auth_failures_per_addr_hour,
                k,
            ),
            // Per app: a steady rate, and twice that as a burst.
            app_sends: Limiter::new(
                clock,
                l.app_sends_per_second.saturating_mul(2),
                l.app_sends_per_second,
                1,
                64,
            ),
        }
    }

    fn prune(&self) {
        for l in [
            &self.instance_reg_addr,
            &self.device_reg_addr_hour,
            &self.device_reg_addr_day,
            &self.handle_create,
            &self.device_update,
            &self.alert_handle,
            &self.sync_handle,
            &self.alert_device,
            &self.sync_device,
            &self.instance_new,
            &self.instance_established,
            &self.unknown_handles,
            &self.auth_failures,
            &self.app_sends,
        ] {
            l.prune();
        }
    }
}

pub struct Inner {
    pub settings: Settings,
    pub db: Db,
    pub keys: Keys,
    pub clock: Clock,
    pub apns: Apns,
    pub limiters: Limiters,
    /// Accepted registration challenges, until they expire.
    pub challenges: TimedSet<[u8; 16]>,
    /// Hashes of (instance, event, handle) for pushes Apple took, for 15 minutes.
    pub events: TimedSet<[u8; 16]>,
    /// Devices Apple told us to back off from (`429`), until a time in ms.
    backoff: Mutex<HashMap<String, i64>>,
    /// Requests being handled; more than the limit are shed.
    pub inflight: Arc<Semaphore>,
}

/// Cheap to clone; derefs to [`Inner`].
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(settings: Settings, db: Db, keys: Keys, clock: Clock, apns: Apns) -> AppState {
        let limits = settings.limits.clone();
        AppState(Arc::new(Inner {
            limiters: Limiters::new(&clock, &limits),
            challenges: TimedSet::new(&clock, limits.challenge_ttl_secs, limits.max_tracked_keys),
            events: TimedSet::new(&clock, EVENT_TTL_SECS, limits.max_tracked_keys),
            backoff: Mutex::new(HashMap::new()),
            inflight: Arc::new(Semaphore::new(limits.max_inflight_requests)),
            settings,
            db,
            keys,
            clock,
            apns,
        }))
    }

    /// Remembers that Apple asked us to back off from a device.
    pub fn set_backoff(&self, device_id: &str, seconds: u64) {
        let until = self.clock.now_ms() + (seconds as i64) * 1000;
        let mut map = self.backoff.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.settings.limits.max_tracked_keys {
            let now = self.clock.now_ms();
            map.retain(|_, u| *u > now);
        }
        if map.len() < self.settings.limits.max_tracked_keys {
            map.insert(device_id.to_string(), until);
        }
    }

    /// Seconds left of a device's backoff, if any.
    pub fn backoff_left(&self, device_id: &str) -> Option<u64> {
        let now = self.clock.now_ms();
        let map = self.backoff.lock().unwrap_or_else(|e| e.into_inner());
        map.get(device_id)
            .filter(|u| **u > now)
            .map(|u| ((*u - now) as u64).div_ceil(1000).max(1))
    }

    /// Drops everything that has expired or refilled. Called by the maintenance task.
    pub fn prune_memory(&self) {
        let now = self.clock.now_ms();
        self.limiters.prune();
        self.challenges.prune();
        self.events.prune();
        self.backoff
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, u| *u > now);
    }
}
