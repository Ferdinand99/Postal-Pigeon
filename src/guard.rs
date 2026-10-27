//! A circuit breaker on the answers that delete devices.
//!
//! `BadDeviceToken` and `DeviceTokenNotForTopic` normally mean one device has
//! a bad token, and three in a row delete it. But the same answers come back
//! for every device when the relay's own configuration is wrong: a wrong
//! bundle id, a key without the right topic, an app registered in the wrong
//! environment. Acting on them then would delete healthy devices in bulk.
//!
//! So the relay watches the answers per app over a short window. When many
//! different devices answer badly, on behalf of several different instances,
//! and the bad answers are a large share of the app's answers, the breaker
//! trips: for a while nothing that was ever working is struck or deleted,
//! `/v1/status` says `degraded` and the log says so loudly.
//!
//! The breaker must not be a lever for an attacker. Registering junk devices is
//! cheap, so only answers about devices that **have had a push accepted**
//! (verified) count toward it, and they must come from at least
//! `trip_instances` different instances. Unverified junk is never counted and
//! is never protected: it is struck and deleted as usual, breaker open or not.

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
    instance: u64,
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
    pub bad_instances: u32,
}

pub struct StrikeGuard {
    clock: Clock,
    window_ms: i64,
    trip_devices: u32,
    trip_instances: u32,
    trip_percent: u32,
    trip_ms: i64,
    inner: Mutex<Inner>,
}

fn hash_of(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

struct Counts {
    answers: u32,
    bad: u32,
    devices: u32,
    instances: u32,
}

fn counts(events: &VecDeque<Event>, since_ms: i64) -> Counts {
    let live = || events.iter().filter(|e| e.at_ms >= since_ms);
    let bad = || live().filter(|e| e.bad);
    Counts {
        answers: live().count() as u32,
        bad: bad().count() as u32,
        devices: bad().map(|e| e.device).collect::<HashSet<_>>().len() as u32,
        instances: bad().map(|e| e.instance).collect::<HashSet<_>>().len() as u32,
    }
}

impl StrikeGuard {
    pub fn new(
        clock: &Clock,
        window_secs: i64,
        trip_devices: u32,
        trip_instances: u32,
        trip_percent: u32,
        trip_secs: i64,
    ) -> Self {
        StrikeGuard {
            clock: clock.clone(),
            window_ms: window_secs * 1000,
            trip_devices,
            trip_instances,
            trip_percent,
            trip_ms: trip_secs * 1000,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn push(&self, app: &str, bad: bool, device_id: &str, instance_id: &str) -> bool {
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
            device: hash_of(device_id),
            instance: hash_of(instance_id),
        });
        if !bad {
            return false;
        }
        let c = counts(events, now - self.window_ms);
        let tripped_now = inner.tripped_until_ms > now;
        if !tripped_now
            && c.devices >= self.trip_devices
            && c.instances >= self.trip_instances
            && u64::from(c.bad) * 100 >= u64::from(self.trip_percent) * u64::from(c.answers)
        {
            inner.tripped_until_ms = now + self.trip_ms;
            tracing::error!(
                app,
                bad_devices = c.devices,
                bad_instances = c.instances,
                answers = c.answers,
                "apns_strike_breaker_open: many working devices are answering as if their token were \
                 bad; the relay's key, team, bundle id or environment is probably wrong. \
                 Working devices are not struck or deleted until it closes. Run `admin check-apns`."
            );
            return true;
        }
        false
    }

    /// Apple gave a non-strike answer for a device of `app`.
    pub fn record_ok(&self, app: &str, device_id: &str) {
        self.push(app, false, device_id, "");
    }

    /// Apple gave a strike-worthy answer for a device of `app` that has had a
    /// push accepted before, sent for `instance_id`. Returns whether this answer
    /// opened the breaker. Do not call it for devices that were never verified.
    pub fn record_bad(&self, app: &str, device_id: &str, instance_id: &str) -> bool {
        self.push(app, true, device_id, instance_id)
    }

    /// Whether striking and deleting of working devices is paused.
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
                let c = counts(events, now - self.window_ms);
                AppRatio {
                    app: app.clone(),
                    answers: c.answers,
                    bad: c.bad,
                    bad_devices: c.devices,
                    bad_instances: c.instances,
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
        StrikeGuard::new(clock, 600, 5, 3, 50, 3600)
    }

    #[test]
    fn a_few_bad_devices_do_not_trip_it() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..4 {
            assert!(!g.record_bad("hedgerow", &format!("d{i}"), &format!("i{}", i % 3)));
        }
        assert!(!g.is_tripped());
    }

    #[test]
    fn many_devices_and_instances_in_a_short_window_trip_it_and_it_closes_later() {
        let clock = Clock::new();
        let g = guard(&clock);
        let mut opened = 0;
        for i in 0..6 {
            if g.record_bad("hedgerow", &format!("d{i}"), &format!("i{}", i % 3)) {
                opened += 1;
            }
        }
        assert_eq!(opened, 1, "it opens once");
        assert!(g.is_tripped());
        clock.advance_secs(3601);
        assert!(!g.is_tripped());
    }

    #[test]
    fn one_or_two_instances_cannot_trip_it() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..50 {
            g.record_bad("hedgerow", &format!("d{i}"), &format!("i{}", i % 2));
        }
        assert!(!g.is_tripped(), "two instances however many devices");
        // A third one is what it takes.
        g.record_bad("hedgerow", "d99", "i-third");
        assert!(g.is_tripped());
    }

    #[test]
    fn one_device_repeating_is_not_many_devices() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..50 {
            g.record_bad("hedgerow", "same", &format!("i{}", i % 5));
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
            g.record_bad("hedgerow", &format!("bad{i}"), &format!("i{}", i % 3));
        }
        assert!(!g.is_tripped(), "6 of 106 is a normal rate of dead tokens");
        let r = g.ratios();
        assert_eq!(
            r,
            vec![AppRatio {
                app: "hedgerow".into(),
                answers: 106,
                bad: 6,
                bad_devices: 6,
                bad_instances: 3,
            }]
        );
    }

    #[test]
    fn old_answers_age_out_of_the_window() {
        let clock = Clock::new();
        let g = guard(&clock);
        for i in 0..4 {
            g.record_bad("hedgerow", &format!("d{i}"), &format!("i{}", i % 3));
        }
        clock.advance_secs(601);
        for i in 4..8 {
            g.record_bad("hedgerow", &format!("d{i}"), &format!("i{}", i % 3));
        }
        assert!(!g.is_tripped(), "never five within one window");
    }
}
