//! A circuit breaker on the answers that delete devices.
//!
//! `BadDeviceToken` and `DeviceTokenNotForTopic` normally mean one device has
//! a bad token, and three in a row delete it. But the same answers (and
//! `BadTopic`, `TopicDisallowed`) come back for every device when the relay's
//! own configuration is wrong: a wrong bundle id, a key without the right
//! topic, an app registered in the wrong environment. Acting on them then would
//! delete healthy devices in bulk.
//!
//! So the relay watches the answers per app over a short window. When many
//! different devices answer badly and the bad answers are a large share of the
//! app's answers, the breaker trips: for a while nothing is struck or deleted,
//! `/v1/status` says `degraded` and the log says so loudly. The same numbers
//! give the per-app ratio shown by `admin stats`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash as _, Hasher as _};
use std::sync::Mutex;

use crate::clock::Clock;

/// Events kept per app at most.
const MAX_EVENTS: usize = 20_000;

struct Event {
    at_ms: i64,
    bad: bool,
    device: u64,
}

#[derive(Default)]
struct Inner {
    apps: HashMap<String, VecDeque<Event>>,
    tripped_until_ms: i64,
}

/// What the guard saw for one app in the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRatio {
    pub app: String,
    pub answers: u32,
    pub bad: u32,
    pub bad_devices: u32,
}

pub struct StrikeGuard {
    clock: Clock,
    window_ms: i64,
    trip_devices: u32,
    trip_percent: u32,
    trip_ms: i64,
    inner: Mutex<Inner>,
}

fn device_hash(device_id: &str) -> u64 {
    let mut h = DefaultHasher::new();
    device_id.hash(&mut h);
    h.finish()
}

impl StrikeGuard {
    pub fn new(
        clock: &Clock,
        window_secs: i64,
        trip_devices: u32,
        trip_percent: u32,
        trip_secs: i64,
    ) -> Self {
        StrikeGuard {
            clock: clock.clone(),
            window_ms: window_secs * 1000,
            trip_devices,
            trip_percent,
            trip_ms: trip_secs * 1000,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn push(&self, app: &str, bad: bool, device_id: &str) -> bool {
        let now = self.clock.now_ms();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let events = inner.apps.entry(app.to_string()).or_default();
        while events
            .front()
            .is_some_and(|e| e.at_ms < now - self.window_ms)
            || events.len() >= MAX_EVENTS
        {
            events.pop_front();
        }
        events.push_back(Event {
            at_ms: now,
            bad,
            device: device_hash(device_id),
        });
        if !bad {
            return false;
        }
        let total = events.len() as u32;
        let bad_count = events.iter().filter(|e| e.bad).count() as u32;
        let bad_devices = events
            .iter()
            .filter(|e| e.bad)
            .map(|e| e.device)
            .collect::<HashSet<_>>()
            .len() as u32;
        let tripped_now = inner.tripped_until_ms > now;
        if !tripped_now
            && bad_devices >= self.trip_devices
            && u64::from(bad_count) * 100 >= u64::from(self.trip_percent) * u64::from(total)
        {
            inner.tripped_until_ms = now + self.trip_ms;
            tracing::error!(
                app,
                bad_devices,
                answers = total,
                "apns_strike_breaker_open: many devices are answering as if their token were bad; \
                 the relay's key, team, bundle id or environment is probably wrong. \
                 Nothing is struck or deleted until it closes. Run `admin check-apns`."
            );
            return true;
        }
        false
    }

    /// Apple took a push for a device of `app`.
    pub fn record_ok(&self, app: &str, device_id: &str) {
        self.push(app, false, device_id);
    }

    /// Apple gave a strike-worthy answer for a device of `app`. Returns
    /// whether this answer opened the breaker.
    pub fn record_bad(&self, app: &str, device_id: &str) -> bool {
        self.push(app, true, device_id)
    }

    /// Whether striking and deleting are paused.
    pub fn is_tripped(&self) -> bool {
        let now = self.clock.now_ms();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tripped_until_ms
            > now
    }

    /// Per-app numbers for the current window.
    pub fn ratios(&self) -> Vec<AppRatio> {
        let now = self.clock.now_ms();
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<AppRatio> = inner
            .apps
            .iter()
            .map(|(app, events)| {
                let live: Vec<&Event> = events
                    .iter()
                    .filter(|e| e.at_ms >= now - self.window_ms)
                    .collect();
                AppRatio {
                    app: app.clone(),
                    answers: live.len() as u32,
                    bad: live.iter().filter(|e| e.bad).count() as u32,
                    bad_devices: live
                        .iter()
                        .filter(|e| e.bad)
                        .map(|e| e.device)
                        .collect::<HashSet<_>>()
                        .len() as u32,
                }
            })
            .collect();
        out.sort_by(|a, b| a.app.cmp(&b.app));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(clock: &Clock) -> StrikeGuard {
        StrikeGuard::new(clock, 600, 5, 50, 3600)
    }

    #[test]
    fn a_few_bad_devices_do_not_trip_it() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..4 {
            assert!(!g.record_bad("hedgerow", &format!("d{i}")));
        }
        assert!(!g.is_tripped());
    }

    #[test]
    fn many_devices_in_a_short_window_trip_it_and_it_closes_later() {
        let clock = Clock::new();
        let g = guard(&clock);
        let mut opened = 0;
        for i in 0..6 {
            if g.record_bad("hedgerow", &format!("d{i}")) {
                opened += 1;
            }
        }
        assert_eq!(opened, 1, "it opens once");
        assert!(g.is_tripped());
        clock.advance_secs(3601);
        assert!(!g.is_tripped());
    }

    #[test]
    fn one_device_repeating_is_not_many_devices() {
        let clock = Clock::new();
        let g = guard(&clock);
        for _ in 0..50 {
            g.record_bad("hedgerow", "same");
        }
        assert!(!g.is_tripped());
    }

    #[test]
    fn mostly_good_answers_keep_it_closed() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..100 {
            g.record_ok("hedgerow", &format!("ok{i}"));
        }
        for i in 0..6 {
            g.record_bad("hedgerow", &format!("bad{i}"));
        }
        assert!(!g.is_tripped(), "6 of 106 is a normal rate of dead tokens");
        let r = g.ratios();
        assert_eq!(
            r,
            vec![AppRatio {
                app: "hedgerow".into(),
                answers: 106,
                bad: 6,
                bad_devices: 6
            }]
        );
    }

    #[test]
    fn old_answers_age_out_of_the_window() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..4 {
            g.record_bad("hedgerow", &format!("d{i}"));
        }
        clock.advance_secs(601);
        for i in 4..8 {
            g.record_bad("hedgerow", &format!("d{i}"));
        }
        assert!(!g.is_tripped(), "never five within one window");
    }
}
