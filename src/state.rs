//! Shared application state.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

use crate::apns::Apns;
use crate::clock::Clock;
use crate::config::Settings;
use crate::crypto::Keys;
use crate::db::Db;
use crate::guard::StrikeGuard;
use crate::limits::{AddrInflight, Limiter, Limits, RecentCounter, TimedSet};

/// How long a handled `event_id` is remembered (seconds).
pub const EVENT_TTL_SECS: i64 = 15 * 60;

/// All the token buckets. Each is keyed by one scope only (an address, an
/// instance, a handle, a device or an app), never by a pair.
pub struct Limiters {
    pub instance_reg_addr: Limiter,
    pub instance_reg_prefix: Limiter,
    pub device_reg_addr_hour: Limiter,
    pub device_reg_addr_day: Limiter,
    pub device_reg_prefix_hour: Limiter,
    pub device_reg_prefix_day: Limiter,
    pub unverified_device: Limiter,
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
            instance_reg_prefix: Limiter::per_day(clock, l.instance_reg_per_prefix_day, k),
            device_reg_prefix_hour: Limiter::per_hour(
                clock,
                l.device_reg_per_prefix_hour,
                l.device_reg_per_prefix_hour,
                k,
            ),
            device_reg_prefix_day: Limiter::per_day(clock, l.device_reg_per_prefix_day, k),
            unverified_device: Limiter::per_hour(
                clock,
                l.unverified_device_per_hour,
                l.unverified_device_per_hour,
                k,
            ),
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
            &self.instance_reg_prefix,
            &self.device_reg_prefix_hour,
            &self.device_reg_prefix_day,
            &self.unverified_device,
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
    /// A small separate pool for /healthz, so it answers while the rest is shed.
    pub health_inflight: Arc<Semaphore>,
    /// Requests in progress per client address.
    pub addr_inflight: AddrInflight,
    /// Instance registrations in the last hour (drives the adaptive proof of work).
    pub registrations: RecentCounter,
    /// Instances registered today (day, count), for the high-water mark.
    registered_today: Mutex<(i64, u32)>,
    /// Pauses striking and deleting when many devices answer badly at once.
    pub guard: StrikeGuard,
    /// When the last "X-Forwarded-For from an untrusted peer" warning was logged (ms).
    xff_warned_ms: AtomicI64,
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
            health_inflight: Arc::new(Semaphore::new(limits.health_inflight_requests)),
            addr_inflight: AddrInflight::new(limits.max_inflight_per_addr),
            registrations: RecentCounter::new(&clock),
            registered_today: Mutex::new((i64::MIN, 0)),
            guard: StrikeGuard::new(
                &clock,
                limits.strike_window_secs,
                limits.strike_trip_devices,
                limits.strike_trip_instances,
                limits.strike_trip_percent,
                limits.strike_trip_secs,
            ),
            xff_warned_ms: AtomicI64::new(i64::MIN),
            settings,
            db,
            keys,
            clock,
            apns,
        }))
    }

    /// `ok`, `degraded` or `unknown`: Apple's recent answers, and whether the
    /// strike breaker is open.
    pub fn apns_status(&self) -> &'static str {
        if self.guard.is_tripped() {
            "degraded"
        } else {
            self.apns.status()
        }
    }

    /// The proof-of-work difficulty to ask for now: the base, plus bits for the
    /// last hour's registration volume, plus more bits above the day's
    /// high-water mark.
    pub fn current_difficulty(&self) -> u32 {
        let l = &self.settings.limits;
        let extra = if self.registration_busy() {
            l.pow_high_water_extra_bits
        } else {
            0
        };
        l.difficulty_for(self.registrations.last_hour()) + extra
    }

    /// Whether today's registrations are above the high-water mark.
    pub fn registration_busy(&self) -> bool {
        let today = self.clock.today();
        let (day, count) = *self
            .registered_today
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        day == today && count >= self.settings.limits.instance_reg_high_water_per_day
    }

    /// Counts a new instance. Logs, once, when the day's high-water mark is
    /// crossed.
    pub fn note_registration(&self) {
        self.registrations.record();
        let today = self.clock.today();
        let mut guard = self
            .registered_today
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if guard.0 != today {
            *guard = (today, 0);
        }
        guard.1 = guard.1.saturating_add(1);
        if guard.1 == self.settings.limits.instance_reg_high_water_per_day {
            tracing::error!(
                registrations = guard.1,
                "registration_high_water: many instances registered today; the proof of work is \
                 harder until tomorrow. Look at `admin instances` for a flood."
            );
        }
    }

    /// Sets today's count from the database at start-up.
    pub fn set_registrations_today(&self, count: u32) {
        *self
            .registered_today
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = (self.clock.today(), count);
    }

    /// Logs, at most once an hour, that a peer we do not trust sent
    /// `X-Forwarded-For`: usually the proxy's address is missing from
    /// `PP_TRUSTED_PROXIES`, and every client then shares one address.
    pub fn note_untrusted_forwarded_for(&self) {
        let now = self.clock.now_ms();
        let last = self.xff_warned_ms.load(Ordering::Relaxed);
        if (last == i64::MIN || now - last >= 3_600_000)
            && self
                .xff_warned_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                "a peer that is not in PP_TRUSTED_PROXIES sent X-Forwarded-For; \
                 if that is your reverse proxy, add its address, or all clients share one address"
            );
        }
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
