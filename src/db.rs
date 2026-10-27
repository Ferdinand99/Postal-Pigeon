//! The SQLite database (docs/design.md section 9).
//!
//! One file in the data directory, WAL mode. Device records and handle records
//! are linked to each other and never to an instance; instance records are never
//! linked to a handle or a device. Dates are day numbers (days since 1970-01-01,
//! UTC), never times of day, except the moment a token was registered
//! (`token_set_ms`), which the `410` rule needs to the millisecond.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension as _, params};

pub type DbResult<T> = Result<T, rusqlite::Error>;

const SCHEMA_V1: &str = "
CREATE TABLE devices (
    id             TEXT PRIMARY KEY,
    key_hash       BLOB NOT NULL,
    app            TEXT NOT NULL,
    environment    TEXT NOT NULL,
    token_sealed   TEXT NOT NULL,
    seal_key_id    TEXT NOT NULL,
    token_fp       BLOB NOT NULL UNIQUE,
    created_day    INTEGER NOT NULL,
    token_set_ms   INTEGER NOT NULL,
    last_seen_day  INTEGER NOT NULL,
    strikes        INTEGER NOT NULL DEFAULT 0,
    verified       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE handles (
    id            TEXT PRIMARY KEY,
    hash          BLOB NOT NULL,
    device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tag           TEXT NOT NULL,
    created_day   INTEGER NOT NULL,
    last_used_day INTEGER
);
CREATE INDEX handles_device ON handles(device_id);
CREATE TABLE instances (
    id            TEXT PRIMARY KEY,
    hash          BLOB NOT NULL,
    product       TEXT NOT NULL,
    version       TEXT NOT NULL,
    tier          TEXT NOT NULL DEFAULT 'new',
    state         TEXT NOT NULL DEFAULT 'active',
    created_day   INTEGER NOT NULL,
    last_used_day INTEGER NOT NULL,
    reg_prefix    TEXT,
    reg_day       INTEGER,
    flagged       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE instance_usage (
    instance_id TEXT NOT NULL,
    day         INTEGER NOT NULL,
    sends       INTEGER NOT NULL DEFAULT 0,
    limited     INTEGER NOT NULL DEFAULT 0,
    failures    INTEGER NOT NULL DEFAULT 0,
    throttled   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (instance_id, day)
);
";

/// The database, shared between request handlers and background tasks.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Opens (and creates, and migrates) the database file.
    pub fn open(path: &Path) -> DbResult<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    /// A private in-memory database. For tests.
    pub fn open_memory() -> DbResult<Db> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> DbResult<Db> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Deleted rows (tokens, handles) are overwritten, not left in free pages.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 1 {
            conn.execute_batch(&format!("BEGIN;{SCHEMA_V1}PRAGMA user_version = 1;COMMIT;"))?;
        }
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` on the connection, in the calling thread.
    pub fn with<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut conn)
    }

    /// Runs `f` on the connection on a blocking thread.
    pub async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> R + Send + 'static,
    ) -> R {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.with(f))
            .await
            .expect("database task")
    }

    /// Whether the database answers.
    pub async fn ping(&self) -> bool {
        self.call(|c| c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).is_ok())
            .await
    }
}

// ---- Instances -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InstanceRow {
    pub id: String,
    pub hash: Vec<u8>,
    pub product: String,
    pub version: String,
    pub tier: String,
    pub state: String,
    pub created_day: i64,
    pub last_used_day: i64,
    pub flagged: bool,
}

const INSTANCE_COLS: &str =
    "id, hash, product, version, tier, state, created_day, last_used_day, flagged";

fn instance_from(r: &rusqlite::Row<'_>) -> DbResult<InstanceRow> {
    Ok(InstanceRow {
        id: r.get(0)?,
        hash: r.get(1)?,
        product: r.get(2)?,
        version: r.get(3)?,
        tier: r.get(4)?,
        state: r.get(5)?,
        created_day: r.get(6)?,
        last_used_day: r.get(7)?,
        flagged: r.get::<_, i64>(8)? != 0,
    })
}

pub fn insert_instance(
    c: &Connection,
    id: &str,
    hash: &[u8],
    product: &str,
    version: &str,
    day: i64,
    prefix: &str,
) -> DbResult<()> {
    c.execute(
        "INSERT INTO instances (id, hash, product, version, created_day, last_used_day, reg_prefix, reg_day)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?5)",
        params![id, hash, product, version, day, prefix],
    )?;
    Ok(())
}

pub fn get_instance(c: &Connection, id: &str) -> DbResult<Option<InstanceRow>> {
    c.query_row(
        &format!("SELECT {INSTANCE_COLS} FROM instances WHERE id = ?1"),
        [id],
        instance_from,
    )
    .optional()
}

pub fn touch_instance(c: &Connection, id: &str, day: i64) -> DbResult<()> {
    c.execute(
        "UPDATE instances SET last_used_day = ?2 WHERE id = ?1 AND last_used_day < ?2",
        params![id, day],
    )?;
    Ok(())
}

pub fn set_instance_hash(c: &Connection, id: &str, hash: &[u8]) -> DbResult<bool> {
    Ok(c.execute(
        "UPDATE instances SET hash = ?2 WHERE id = ?1",
        params![id, hash],
    )? > 0)
}

pub fn delete_instance(c: &Connection, id: &str) -> DbResult<bool> {
    c.execute("DELETE FROM instance_usage WHERE instance_id = ?1", [id])?;
    Ok(c.execute("DELETE FROM instances WHERE id = ?1", [id])? > 0)
}

pub fn count_instances_created_on(c: &Connection, day: i64) -> DbResult<i64> {
    c.query_row(
        "SELECT COUNT(*) FROM instances WHERE created_day = ?1",
        [day],
        |r| r.get(0),
    )
}

pub fn set_instance_state(c: &Connection, id: &str, state: &str) -> DbResult<bool> {
    Ok(c.execute(
        "UPDATE instances SET state = ?2 WHERE id = ?1",
        params![id, state],
    )? > 0)
}

pub fn set_instance_tier(c: &Connection, id: &str, tier: &str) -> DbResult<bool> {
    Ok(c.execute(
        "UPDATE instances SET tier = ?2 WHERE id = ?1",
        params![id, tier],
    )? > 0)
}

pub fn flag_instance(c: &Connection, id: &str) -> DbResult<()> {
    c.execute("UPDATE instances SET flagged = 1 WHERE id = ?1", [id])?;
    Ok(())
}

/// Counts to add to an instance's usage for one day.
#[derive(Debug, Default, Clone, Copy)]
pub struct Usage {
    pub sends: i64,
    pub limited: i64,
    pub failures: i64,
    pub throttled: i64,
}

/// Adds to an instance's counters for `day` and returns today's `throttled` total.
pub fn add_usage(c: &Connection, id: &str, day: i64, u: Usage) -> DbResult<i64> {
    c.execute(
        "INSERT INTO instance_usage (instance_id, day, sends, limited, failures, throttled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (instance_id, day) DO UPDATE SET
            sends = sends + excluded.sends,
            limited = limited + excluded.limited,
            failures = failures + excluded.failures,
            throttled = throttled + excluded.throttled",
        params![id, day, u.sends, u.limited, u.failures, u.throttled],
    )?;
    c.query_row(
        "SELECT throttled FROM instance_usage WHERE instance_id = ?1 AND day = ?2",
        params![id, day],
        |r| r.get(0),
    )
}

/// What `admin instances` shows.
#[derive(Debug, Clone)]
pub struct InstanceSummary {
    pub row: InstanceRow,
    pub sends_7d: i64,
}

pub fn list_instances(c: &Connection, today: i64) -> DbResult<Vec<InstanceSummary>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {INSTANCE_COLS},
                COALESCE((SELECT SUM(sends) FROM instance_usage u
                          WHERE u.instance_id = instances.id AND u.day > ?1), 0)
         FROM instances ORDER BY created_day DESC, id"
    ))?;
    let rows = stmt.query_map([today - 7], |r| {
        Ok(InstanceSummary {
            row: instance_from(r)?,
            sends_7d: r.get(9)?,
        })
    })?;
    rows.collect()
}

// ---- Devices -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: String,
    pub key_hash: Vec<u8>,
    pub app: String,
    pub environment: String,
    pub token_sealed: String,
    pub seal_key_id: String,
    pub created_day: i64,
    pub token_set_ms: i64,
    pub last_seen_day: i64,
    pub strikes: i64,
    /// Whether Apple has ever accepted a push for this device.
    pub verified: bool,
}

const DEVICE_COLS: &str = "d.id, d.key_hash, d.app, d.environment, d.token_sealed, d.seal_key_id, \
                           d.created_day, d.token_set_ms, d.last_seen_day, d.strikes, d.verified";

fn device_from(r: &rusqlite::Row<'_>) -> DbResult<DeviceRow> {
    device_from_at(r, 0)
}

fn device_from_at(r: &rusqlite::Row<'_>, o: usize) -> DbResult<DeviceRow> {
    Ok(DeviceRow {
        id: r.get(o)?,
        key_hash: r.get(o + 1)?,
        app: r.get(o + 2)?,
        environment: r.get(o + 3)?,
        token_sealed: r.get(o + 4)?,
        seal_key_id: r.get(o + 5)?,
        created_day: r.get(o + 6)?,
        token_set_ms: r.get(o + 7)?,
        last_seen_day: r.get(o + 8)?,
        strikes: r.get(o + 9)?,
        verified: r.get::<_, i64>(o + 10)? != 0,
    })
}

/// A device to insert. The token arrives already sealed.
pub struct NewDevice<'a> {
    pub id: &'a str,
    pub key_hash: &'a [u8],
    pub app: &'a str,
    pub environment: &'a str,
    pub token_sealed: &'a str,
    pub seal_key_id: &'a str,
    pub token_fp: &'a [u8],
    pub day: i64,
    pub now_ms: i64,
}

/// Inserts a device. A record with the same token is replaced, and its device
/// id and handles stop working.
pub fn insert_device(c: &mut Connection, d: &NewDevice<'_>) -> DbResult<()> {
    let tx = c.transaction()?;
    tx.execute("DELETE FROM devices WHERE token_fp = ?1", [d.token_fp])?;
    tx.execute(
        "INSERT INTO devices (id, key_hash, app, environment, token_sealed, seal_key_id, token_fp,
                              created_day, token_set_ms, last_seen_day)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?8)",
        params![
            d.id,
            d.key_hash,
            d.app,
            d.environment,
            d.token_sealed,
            d.seal_key_id,
            d.token_fp,
            d.day,
            d.now_ms
        ],
    )?;
    tx.commit()
}

pub fn count_devices(c: &Connection) -> DbResult<i64> {
    c.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
}

pub fn get_device(c: &Connection, id: &str) -> DbResult<Option<DeviceRow>> {
    c.query_row(
        &format!("SELECT {DEVICE_COLS} FROM devices d WHERE d.id = ?1"),
        [id],
        device_from,
    )
    .optional()
}

/// Replaces a device's token (APNs rotated it). Another record that held the
/// same token is removed.
#[allow(clippy::too_many_arguments)]
pub fn update_device_token(
    c: &mut Connection,
    id: &str,
    environment: &str,
    sealed: &str,
    seal_key_id: &str,
    fp: &[u8],
    now_ms: i64,
    day: i64,
) -> DbResult<bool> {
    let tx = c.transaction()?;
    tx.execute(
        "DELETE FROM devices WHERE token_fp = ?1 AND id != ?2",
        params![fp, id],
    )?;
    let n = tx.execute(
        "UPDATE devices SET environment = ?2, token_sealed = ?3, seal_key_id = ?4, token_fp = ?5,
                token_set_ms = ?6, last_seen_day = ?7, strikes = 0
         WHERE id = ?1",
        params![id, environment, sealed, seal_key_id, fp, now_ms, day],
    )?;
    tx.commit()?;
    Ok(n > 0)
}

pub fn delete_device(c: &Connection, id: &str) -> DbResult<bool> {
    Ok(c.execute("DELETE FROM devices WHERE id = ?1", [id])? > 0)
}

/// A keep-alive: sets the last-seen date.
pub fn touch_device(c: &Connection, id: &str, day: i64) -> DbResult<()> {
    c.execute(
        "UPDATE devices SET last_seen_day = MAX(last_seen_day, ?2) WHERE id = ?1",
        params![id, day],
    )?;
    Ok(())
}

/// Apple accepted a push: the device is real. Sets the last-seen date, clears
/// strikes and ends the small send quota of a device that was never verified.
pub fn mark_verified(c: &Connection, id: &str, day: i64) -> DbResult<()> {
    c.execute(
        "UPDATE devices SET last_seen_day = MAX(last_seen_day, ?2), strikes = 0, verified = 1
         WHERE id = ?1",
        params![id, day],
    )?;
    Ok(())
}

/// Counts a `BadDeviceToken` strike and returns the new count.
pub fn add_strike(c: &Connection, id: &str) -> DbResult<i64> {
    c.execute(
        "UPDATE devices SET strikes = strikes + 1 WHERE id = ?1",
        [id],
    )?;
    Ok(
        c.query_row("SELECT strikes FROM devices WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or(0),
    )
}

/// Deletes a device for an `Unregistered` answer, but only if its token was
/// registered before `apple_ms` (Apple's timestamp), so a token registered a
/// moment ago isn't deleted by an old answer.
pub fn delete_device_unregistered(c: &Connection, id: &str, apple_ms: i64) -> DbResult<bool> {
    Ok(c.execute(
        "DELETE FROM devices WHERE id = ?1 AND token_set_ms < ?2",
        params![id, apple_ms],
    )? > 0)
}

/// Devices whose token is sealed under a key other than `current`.
pub fn devices_to_reseal(
    c: &Connection,
    current: &str,
    limit: i64,
) -> DbResult<Vec<(String, String, String)>> {
    let mut stmt = c.prepare(
        "SELECT id, seal_key_id, token_sealed FROM devices WHERE seal_key_id != ?1 LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![current, limit], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })?;
    rows.collect()
}

/// Replaces a sealed token only if the row still holds the value that was read
/// (compare-and-swap), so re-sealing can't overwrite a token the app rotated in
/// the meantime. Returns whether it wrote.
pub fn set_sealed_if(
    c: &Connection,
    id: &str,
    old_key_id: &str,
    old_sealed: &str,
    new_key_id: &str,
    new_sealed: &str,
) -> DbResult<bool> {
    Ok(c.execute(
        "UPDATE devices SET seal_key_id = ?4, token_sealed = ?5
         WHERE id = ?1 AND seal_key_id = ?2 AND token_sealed = ?3",
        params![id, old_key_id, old_sealed, new_key_id, new_sealed],
    )? > 0)
}

/// Whether a device with this token fingerprint exists (registering it again
/// replaces it, so it doesn't add a row).
pub fn device_fp_exists(c: &Connection, fp: &[u8]) -> DbResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM devices WHERE token_fp = ?1",
        [fp],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

/// Folds the write-ahead log into the database file and truncates it, so
/// deleted rows don't linger in the log.
pub fn checkpoint(c: &Connection) -> DbResult<()> {
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
}

// ---- Handles -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HandleRow {
    pub id: String,
    pub hash: Vec<u8>,
    pub device_id: String,
    pub tag: String,
    pub created_day: i64,
    pub last_used_day: Option<i64>,
}

fn handle_from(r: &rusqlite::Row<'_>) -> DbResult<HandleRow> {
    Ok(HandleRow {
        id: r.get(0)?,
        hash: r.get(1)?,
        device_id: r.get(2)?,
        tag: r.get(3)?,
        created_day: r.get(4)?,
        last_used_day: r.get(5)?,
    })
}

pub fn insert_handle(
    c: &Connection,
    id: &str,
    hash: &[u8],
    device_id: &str,
    tag: &str,
    day: i64,
) -> DbResult<()> {
    c.execute(
        "INSERT INTO handles (id, hash, device_id, tag, created_day) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, hash, device_id, tag, day],
    )?;
    Ok(())
}

pub fn count_handles(c: &Connection, device_id: &str) -> DbResult<i64> {
    c.query_row(
        "SELECT COUNT(*) FROM handles WHERE device_id = ?1",
        [device_id],
        |r| r.get(0),
    )
}

pub fn list_handles(c: &Connection, device_id: &str) -> DbResult<Vec<HandleRow>> {
    let mut stmt = c.prepare(
        "SELECT id, hash, device_id, tag, created_day, last_used_day FROM handles
         WHERE device_id = ?1 ORDER BY created_day, id",
    )?;
    let rows = stmt.query_map([device_id], handle_from)?;
    rows.collect()
}

/// Revokes one handle of a device.
pub fn delete_handle(c: &Connection, device_id: &str, handle_id: &str) -> DbResult<bool> {
    Ok(c.execute(
        "DELETE FROM handles WHERE id = ?1 AND device_id = ?2",
        params![handle_id, device_id],
    )? > 0)
}

/// A handle and the device it belongs to.
pub fn get_handle_with_device(
    c: &Connection,
    handle_id: &str,
) -> DbResult<Option<(HandleRow, DeviceRow)>> {
    c.query_row(
        &format!(
            "SELECT h.id, h.hash, h.device_id, h.tag, h.created_day, h.last_used_day, {DEVICE_COLS}
             FROM handles h JOIN devices d ON d.id = h.device_id WHERE h.id = ?1"
        ),
        [handle_id],
        |r| Ok((handle_from(r)?, device_from_at(r, 6)?)),
    )
    .optional()
}

pub fn touch_handle_used(c: &Connection, handle_id: &str, day: i64) -> DbResult<()> {
    c.execute(
        "UPDATE handles SET last_used_day = ?2 WHERE id = ?1",
        params![handle_id, day],
    )?;
    Ok(())
}

// ---- Maintenance and statistics -------------------------------------------

/// Deletes devices not seen since before `before_day` (their handles go too).
pub fn expire_devices(c: &Connection, before_day: i64) -> DbResult<usize> {
    c.execute("DELETE FROM devices WHERE last_seen_day < ?1", [before_day])
}

/// Deletes instances not used since before `before_day`, with their usage.
pub fn expire_instances(c: &Connection, before_day: i64) -> DbResult<usize> {
    c.execute(
        "DELETE FROM instance_usage WHERE instance_id IN
            (SELECT id FROM instances WHERE last_used_day < ?1)",
        [before_day],
    )?;
    c.execute(
        "DELETE FROM instances WHERE last_used_day < ?1",
        [before_day],
    )
}

pub fn expire_usage(c: &Connection, before_day: i64) -> DbResult<usize> {
    c.execute("DELETE FROM instance_usage WHERE day < ?1", [before_day])
}

/// Forgets the registration address prefix of instances older than the cutoff.
pub fn clear_prefixes(c: &Connection, before_day: i64) -> DbResult<usize> {
    c.execute(
        "UPDATE instances SET reg_prefix = NULL WHERE reg_prefix IS NOT NULL AND reg_day < ?1",
        [before_day],
    )
}

/// "new" instances that have had no limit hit for `after_days` become "established".
pub fn promote_tiers(c: &Connection, today: i64, after_days: i64) -> DbResult<usize> {
    c.execute(
        "UPDATE instances SET tier = 'established'
         WHERE tier = 'new' AND state = 'active' AND flagged = 0 AND created_day <= ?1
           AND NOT EXISTS (SELECT 1 FROM instance_usage u
                           WHERE u.instance_id = instances.id AND u.day > ?1
                             AND (u.limited > 0 OR u.throttled > 0))",
        [today - after_days],
    )
}

pub fn count_stale_devices(c: &Connection, before_day: i64) -> DbResult<i64> {
    c.query_row(
        "SELECT COUNT(*) FROM devices WHERE last_seen_day < ?1",
        [before_day],
        |r| r.get(0),
    )
}

/// Aggregate numbers for `admin stats`. Nothing here links an instance to a device.
#[derive(Debug, Default)]
pub struct Stats {
    pub instances: Vec<(String, String, i64)>,
    pub flagged_instances: i64,
    pub devices: Vec<(String, String, i64)>,
    pub stale_devices: i64,
    pub handles: i64,
    pub sends_today: Usage,
    pub sends_7d: Usage,
}

pub fn stats(c: &Connection, today: i64) -> DbResult<Stats> {
    let group = |sql: &str| -> DbResult<Vec<(String, String, i64)>> {
        let mut stmt = c.prepare(sql)?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    };
    let usage = |since: i64| -> DbResult<Usage> {
        c.query_row(
            "SELECT COALESCE(SUM(sends),0), COALESCE(SUM(limited),0),
                    COALESCE(SUM(failures),0), COALESCE(SUM(throttled),0)
             FROM instance_usage WHERE day >= ?1",
            [since],
            |r| {
                Ok(Usage {
                    sends: r.get(0)?,
                    limited: r.get(1)?,
                    failures: r.get(2)?,
                    throttled: r.get(3)?,
                })
            },
        )
    };
    Ok(Stats {
        instances: group(
            "SELECT tier, state, COUNT(*) FROM instances GROUP BY tier, state ORDER BY tier, state",
        )?,
        flagged_instances: c.query_row(
            "SELECT COUNT(*) FROM instances WHERE flagged = 1",
            [],
            |r| r.get(0),
        )?,
        devices: group(
            "SELECT app, environment, COUNT(*) FROM devices GROUP BY app, environment ORDER BY app, environment",
        )?,
        stale_devices: count_stale_devices(c, today - 60)?,
        handles: c.query_row("SELECT COUNT(*) FROM handles", [], |r| r.get(0))?,
        sends_today: usage(today)?,
        sends_7d: usage(today - 6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device<'a>(id: &'a str, fp: &'a [u8]) -> NewDevice<'a> {
        NewDevice {
            id,
            key_hash: b"k",
            app: "hedgerow",
            environment: "production",
            token_sealed: "s",
            seal_key_id: "kid",
            token_fp: fp,
            day: 10,
            now_ms: 1000,
        }
    }

    #[test]
    fn same_token_replaces_the_record_and_its_handles() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            insert_handle(c, "h1", b"x", "d1", "tag", 10).unwrap();
            insert_device(c, &device("d2", b"fp")).unwrap();
            assert!(get_device(c, "d1").unwrap().is_none());
            assert!(get_handle_with_device(c, "h1").unwrap().is_none());
            assert!(get_device(c, "d2").unwrap().is_some());
        });
    }

    #[test]
    fn unregistered_only_deletes_older_tokens() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            assert!(!delete_device_unregistered(c, "d1", 500).unwrap());
            assert!(delete_device_unregistered(c, "d1", 2000).unwrap());
        });
    }

    #[test]
    fn strikes_and_touch() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            assert_eq!(add_strike(c, "d1").unwrap(), 1);
            assert_eq!(add_strike(c, "d1").unwrap(), 2);
            touch_device(c, "d1", 11).unwrap();
            assert_eq!(
                get_device(c, "d1").unwrap().unwrap().strikes,
                2,
                "a keep-alive is not a success"
            );
            assert!(!get_device(c, "d1").unwrap().unwrap().verified);
            mark_verified(c, "d1", 11).unwrap();
            let d = get_device(c, "d1").unwrap().unwrap();
            assert_eq!((d.strikes, d.verified, d.last_seen_day), (0, true, 11));
        });
    }

    #[test]
    fn resealing_is_compare_and_swap() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            // The row still holds what was read: written.
            assert!(set_sealed_if(c, "d1", "kid", "s", "new", "s2").unwrap());
            // Someone changed it since (a rotated token, another re-seal): not written.
            assert!(!set_sealed_if(c, "d1", "kid", "s", "newer", "s3").unwrap());
            let d = get_device(c, "d1").unwrap().unwrap();
            assert_eq!(
                (d.seal_key_id.as_str(), d.token_sealed.as_str()),
                ("new", "s2")
            );
        });
    }

    #[test]
    fn fingerprint_lookup() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            assert!(device_fp_exists(c, b"fp").unwrap());
            assert!(!device_fp_exists(c, b"other").unwrap());
        });
    }

    #[test]
    fn secure_delete_and_checkpoint_on_a_file_database() {
        let dir = std::env::temp_dir().join(format!("pp-db-{}", crate::util::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.sqlite");
        let db = Db::open(&path).unwrap();
        db.with(|c| {
            let on: i64 = c
                .query_row("PRAGMA secure_delete", [], |r| r.get(0))
                .unwrap();
            assert_eq!(on, 1, "deleted rows are overwritten");
            for i in 0..50 {
                let id = format!("d{i}");
                let fp = [i as u8; 4];
                insert_device(c, &device(&id, &fp)).unwrap();
            }
            let wal = dir.join("t.sqlite-wal");
            assert!(
                std::fs::metadata(&wal).unwrap().len() > 0,
                "writes sit in the log"
            );
            checkpoint(c).unwrap();
            assert_eq!(
                std::fs::metadata(&wal).unwrap().len(),
                0,
                "the log is truncated"
            );
        });
        drop(db);
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn deleting_a_device_removes_its_handles() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_device(c, &device("d1", b"fp")).unwrap();
            insert_handle(c, "h1", b"x", "d1", "tag", 10).unwrap();
            assert!(delete_device(c, "d1").unwrap());
            assert_eq!(count_handles(c, "d1").unwrap(), 0);
        });
    }

    #[test]
    fn usage_accumulates() {
        let db = Db::open_memory().unwrap();
        db.with(|c| {
            insert_instance(c, "i1", b"h", "vigilant-vole", "0.1", 10, "1.2.3.0/24").unwrap();
            let u = Usage {
                throttled: 2,
                sends: 1,
                ..Usage::default()
            };
            assert_eq!(add_usage(c, "i1", 10, u).unwrap(), 2);
            assert_eq!(add_usage(c, "i1", 10, u).unwrap(), 4);
            assert_eq!(add_usage(c, "i1", 11, u).unwrap(), 2);
        });
    }
}
