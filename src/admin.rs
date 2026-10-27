//! Command-line administration (`postal-pigeon admin ...`), run inside the
//! container. There is no admin web page (docs/design.md section 17).
//!
//! Output never contains a device token, a handle, a credential or an address.

use std::fmt::Write as _;

use clap::Subcommand;

use crate::api::push::{Message, Status, deliver};
use crate::apns::{Outcome, PushRequest, default_ttl_secs};
use crate::config::Kind;
use crate::crypto::{PREFIX_HANDLE, ct_eq, is_device_id, parse_id_secret};
use crate::db;
use crate::maintenance;
use crate::state::AppState;
use crate::util::{b64, day_string, random_bytes};

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// List the registered instances.
    Instances,
    /// Suspend an instance (it gets `403 suspended`).
    BlockInstance {
        /// The instance id shown by `admin instances`.
        id: String,
    },
    /// Lift a suspension (the instance starts again in the "new" tier).
    UnblockInstance { id: String },
    /// Set an instance's tier: new or established.
    SetTier { id: String, tier: String },
    /// Delete an instance's registration.
    DeleteInstance { id: String },
    /// Delete a device and all its handles.
    DeleteDevice {
        /// The device id (hrd_...).
        id: String,
    },
    /// Numbers about instances, devices and sends.
    Stats,
    /// Push a test alert to a registered device, with no rate limits.
    SendTest {
        /// A handle (hrh_...) or a device id (hrd_...) of a registered device.
        #[arg(long)]
        device: String,
        /// alert (the default) or sync.
        #[arg(long, default_value = "alert")]
        kind: String,
    },
    /// Check the APNs key, team and topics against Apple without touching any
    /// device or the database. Run it after deploying and after changing the key.
    CheckApns,
    /// Re-seal device tokens under the current seal key now.
    Reseal,
    /// Run the housekeeping pass now (retention, tiers, re-sealing).
    Maintain,
}

/// Runs a command and returns what to print.
pub async fn run(state: &AppState, cmd: AdminCommand) -> Result<String, String> {
    let db_err = |_: rusqlite::Error| "database error".to_string();
    match cmd {
        AdminCommand::Instances => {
            let today = state.clock.today();
            let rows = state
                .db
                .with(|c| db::list_instances(c, today))
                .map_err(db_err)?;
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{:<12} {:<16} {:<10} {:<12} {:<10} {:<11} {:<11} {:<8} SENDS 7D",
                "ID", "PRODUCT", "VERSION", "TIER", "STATE", "CREATED", "LAST USED", "FLAGGED"
            );
            for s in rows {
                let r = s.row;
                let _ = writeln!(
                    out,
                    "{:<12} {:<16} {:<10} {:<12} {:<10} {:<11} {:<11} {:<8} {}",
                    r.id,
                    r.product,
                    r.version,
                    r.tier,
                    r.state,
                    day_string(r.created_day),
                    day_string(r.last_used_day),
                    if r.flagged { "yes" } else { "-" },
                    s.sends_7d
                );
            }
            Ok(out)
        }
        AdminCommand::BlockInstance { id } => {
            let ok = state
                .db
                .with(|c| db::set_instance_state(c, &id, "suspended"))
                .map_err(db_err)?;
            found(ok, "suspended")
        }
        AdminCommand::UnblockInstance { id } => {
            let ok = state
                .db
                .with(|c| {
                    let ok = db::set_instance_state(c, &id, "active")?;
                    db::set_instance_tier(c, &id, "new")?;
                    c.execute("UPDATE instances SET flagged = 0 WHERE id = ?1", [&id])?;
                    Ok::<_, rusqlite::Error>(ok)
                })
                .map_err(db_err)?;
            found(ok, "active again, in the new tier")
        }
        AdminCommand::SetTier { id, tier } => {
            if tier != "new" && tier != "established" {
                return Err("tier must be new or established".into());
            }
            let ok = state
                .db
                .with(|c| db::set_instance_tier(c, &id, &tier))
                .map_err(db_err)?;
            found(ok, "tier changed")
        }
        AdminCommand::DeleteInstance { id } => {
            let ok = state
                .db
                .with(|c| db::delete_instance(c, &id))
                .map_err(db_err)?;
            found(ok, "deleted")
        }
        AdminCommand::DeleteDevice { id } => {
            let ok = state
                .db
                .with(|c| db::delete_device(c, &id))
                .map_err(db_err)?;
            found(ok, "deleted")
        }
        AdminCommand::Stats => {
            let s = state
                .db
                .with(|c| db::stats(c, state.clock.today()))
                .map_err(db_err)?;
            let mut out = String::new();
            let _ = writeln!(out, "instances:");
            for (tier, st, n) in &s.instances {
                let _ = writeln!(out, "  {tier} / {st}: {n}");
            }
            let _ = writeln!(out, "  flagged for review: {}", s.flagged_instances);
            let _ = writeln!(out, "devices:");
            for (app, env, n) in &s.devices {
                let _ = writeln!(out, "  {app} / {env}: {n}");
            }
            let _ = writeln!(out, "  not seen for 60 days: {}", s.stale_devices);
            let _ = writeln!(out, "handles: {}", s.handles);
            for (label, u) in [("today", &s.sends_today), ("last 7 days", &s.sends_7d)] {
                let _ = writeln!(
                    out,
                    "sends {label}: {} accepted, {} limited, {} failed, {} requests throttled",
                    u.sends, u.limited, u.failures, u.throttled
                );
            }
            let _ = writeln!(out, "apns: {}", state.apns_status());
            Ok(out)
        }
        AdminCommand::SendTest { device, kind } => {
            let kind = Kind::parse(&kind).ok_or("kind must be alert or sync")?;
            let target = find_device(state, &device)?;
            let (dev, tag) = target.ok_or("no such handle or device")?;
            let status = deliver(
                state,
                &dev,
                &tag,
                &Message {
                    kind,
                    reference: Some("test"),
                    collapse: None,
                    ttl_secs: default_ttl_secs(kind),
                    scope: &dev.id,
                },
            )
            .await;
            Ok(format!("{}\n", describe(&status)))
        }
        AdminCommand::CheckApns => check_apns(state).await,
        AdminCommand::Reseal => {
            let n = maintenance::reseal(state).map_err(db_err)?;
            Ok(format!("re-sealed {n} tokens\n"))
        }
        AdminCommand::Maintain => {
            let r = maintenance::run_once(state).map_err(db_err)?;
            Ok(format!("{r:#?}\n"))
        }
    }
}

fn found(ok: bool, what: &str) -> Result<String, String> {
    if ok {
        Ok(format!("{what}\n"))
    } else {
        Err("no such record".into())
    }
}

fn describe(s: &Status) -> String {
    match s {
        Status::Accepted => "accepted: Apple took the push".into(),
        Status::Gone => "gone: the device is not valid (it was removed if Apple said so)".into(),
        Status::Limited(n) => format!("limited: Apple asked to back off for {n} s"),
        Status::Unavailable(_) => "unavailable: Apple or the relay could not deliver now".into(),
        Status::Duplicate => "duplicate".into(),
        Status::UnsupportedKind => "unsupported kind".into(),
    }
}

/// A handle or a device id to the device and the tag to push with.
fn find_device(state: &AppState, given: &str) -> Result<Option<(db::DeviceRow, String)>, String> {
    if is_device_id(given) {
        let d = state
            .db
            .with(|c| db::get_device(c, given))
            .map_err(|_| "database error")?;
        return Ok(d.map(|d| (d, b64(&random_bytes::<16>()))));
    }
    let Some((id, hash)) = parse_id_secret(PREFIX_HANDLE, given) else {
        return Err("expected a handle (hrh_...) or a device id (hrd_...)".into());
    };
    let found = state
        .db
        .with(|c| db::get_handle_with_device(c, &id))
        .map_err(|_| "database error")?;
    Ok(found
        .filter(|(h, _)| ct_eq(&h.hash, &hash))
        .map(|(h, d)| (d, h.tag)))
}

/// Sends a push for a made-up device token to every configured app and
/// environment, and reads Apple's answer. Apple checks the provider token and
/// the topic before it looks at the device token, so `BadDeviceToken` for the
/// made-up token means the key, team and topic were accepted. Nothing is
/// deleted or recorded. A wrong environment can only be told with a real
/// device: use `send-test` for that.
async fn check_apns(state: &AppState) -> Result<String, String> {
    let token = "00".repeat(32);
    let mut out = String::new();
    let mut failed = false;
    for app in &state.settings.apps {
        for env in &state.settings.environments {
            let outcome = state
                .apns
                .send(&PushRequest {
                    token: &token,
                    env: *env,
                    topic: &app.bundle_id,
                    kind: Kind::Sync,
                    tag: "probe",
                    reference: None,
                    collapse: None,
                    ttl_secs: 60,
                })
                .await;
            let (ok, text) = match outcome {
                Outcome::BadToken
                | Outcome::Unregistered { .. }
                | Outcome::Accepted
                | Outcome::TooManyRequests { .. } => (
                    true,
                    "ok: Apple accepted the key, the team and the topic".to_string(),
                ),
                Outcome::ConfigError(r) => (
                    false,
                    format!(
                        "FAILED: Apple refused the topic ({r}). Check the bundle id in PP_APPS and that \
                         the key belongs to the team that owns the app"
                    ),
                ),
                Outcome::OperatorProblem(r) => (
                    false,
                    format!(
                        "FAILED: Apple refused the provider token ({r}). Check PP_APNS_KEY_ID, \
                         PP_APNS_TEAM_ID and the .p8 file"
                    ),
                ),
                Outcome::RelayBackoff { retry_after } => (
                    false,
                    format!("WAIT: Apple asked the relay to back off for {retry_after} s"),
                ),
                Outcome::Failed => (false, "FAILED: could not reach Apple".to_string()),
            };
            failed |= !ok;
            let _ = writeln!(out, "{} {}: {text}", app.id, env.as_str());
        }
    }
    let _ = writeln!(
        out,
        "A wrong environment shows only with a real device: use `admin send-test`."
    );
    if failed { Err(out) } else { Ok(out) }
}
