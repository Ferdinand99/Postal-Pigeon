//! Housekeeping: retention (docs/design.md section 9), tiers, re-sealing.

use std::time::Duration;

use crate::db;
use crate::state::AppState;

/// Devices not seen for this many days are deleted.
pub const DEVICE_RETENTION_DAYS: i64 = 90;
/// Devices not seen for this many days are only flagged (counted in `admin stats`).
pub const DEVICE_STALE_DAYS: i64 = 60;
/// Instances unused for this many days are deleted.
pub const INSTANCE_RETENTION_DAYS: i64 = 180;
/// Usage rows are kept this many days.
pub const USAGE_RETENTION_DAYS: i64 = 30;
/// The registration address prefix is kept this many days.
pub const PREFIX_RETENTION_DAYS: i64 = 30;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub devices_expired: usize,
    pub instances_expired: usize,
    pub usage_expired: usize,
    pub prefixes_cleared: usize,
    pub promoted: usize,
    pub resealed: usize,
    pub stale_devices: i64,
}

/// One pass of everything. Safe to run at any time and any number of times.
pub fn run_once(state: &AppState) -> Result<Report, rusqlite::Error> {
    let today = state.clock.today();
    let after = state.settings.limits.established_after_days;
    let mut report = state.db.with(|c| {
        Ok::<_, rusqlite::Error>(Report {
            devices_expired: db::expire_devices(c, today - DEVICE_RETENTION_DAYS)?,
            instances_expired: db::expire_instances(c, today - INSTANCE_RETENTION_DAYS)?,
            usage_expired: db::expire_usage(c, today - USAGE_RETENTION_DAYS)?,
            prefixes_cleared: db::clear_prefixes(c, today - PREFIX_RETENTION_DAYS)?,
            promoted: db::promote_tiers(c, today, after)?,
            stale_devices: db::count_stale_devices(c, today - DEVICE_STALE_DAYS)?,
            ..Report::default()
        })
    })?;
    report.resealed = reseal(state)?;
    // Fold the write-ahead log into the file and truncate it, so deleted rows
    // do not linger in it.
    state.db.with(|c| db::checkpoint(c))?;
    state.prune_memory();
    Ok(report)
}

/// Re-seals tokens that an older key sealed. Tokens whose key is gone stay as
/// they are (they can't be used; the app registers again when sends fail).
pub fn reseal(state: &AppState) -> Result<usize, rusqlite::Error> {
    let current = state.keys.current_seal_id().to_string();
    let mut done = 0;
    loop {
        let batch = state.db.with(|c| db::devices_to_reseal(c, &current, 500))?;
        if batch.is_empty() {
            return Ok(done);
        }
        let mut progressed = 0;
        for (id, kid, sealed) in batch {
            let Ok(plain) = state.keys.open(&kid, &sealed, &id) else {
                continue;
            };
            let (new_kid, new_sealed) = state.keys.seal(&plain, &id);
            // Only if the row still holds what was read: a token the app rotated
            // in the meantime must not be overwritten with the old one.
            let swapped = state
                .db
                .with(|c| db::set_sealed_if(c, &id, &kid, &sealed, &new_kid, &new_sealed))?;
            if swapped {
                progressed += 1;
            }
        }
        done += progressed;
        if progressed == 0 {
            // Only unreadable ones are left.
            return Ok(done);
        }
    }
}

/// Runs [`run_once`] now and then every hour, forever.
pub async fn run_forever(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let s = state.clone();
        match tokio::task::spawn_blocking(move || run_once(&s)).await {
            Ok(Ok(r)) => tracing::info!(
                devices_expired = r.devices_expired,
                instances_expired = r.instances_expired,
                promoted = r.promoted,
                resealed = r.resealed,
                stale_devices = r.stale_devices,
                "maintenance"
            ),
            _ => tracing::error!("maintenance_failed"),
        }
        for r in state.guard.ratios() {
            tracing::info!(
                app = %r.app,
                answers = r.answers,
                bad = r.bad,
                bad_devices = r.bad_devices,
                "apns_bad_token_ratio"
            );
        }
    }
}
