//! Building the application and serving it.

use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tower::ServiceExt as _;

use crate::api;
use crate::apns::Apns;
use crate::clock::Clock;
use crate::config::Settings;
use crate::crypto::{Keys, read_key_file};
use crate::db::Db;
use crate::limits::Limits;
use crate::maintenance;
use crate::state::AppState;

/// The database file inside the data directory.
pub const DB_FILE: &str = "pigeon.sqlite";

/// Opens the database, loads the keys and the APNs key.
pub fn build_state(settings: Settings) -> Result<AppState, Box<dyn Error>> {
    settings.check_apns_urls()?;
    std::fs::create_dir_all(&settings.data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ =
            std::fs::set_permissions(&settings.data_dir, std::fs::Permissions::from_mode(0o700));
    }

    let seal_file = settings
        .seal_key_file
        .as_ref()
        .ok_or("PP_SEAL_KEY_FILE is required (create one with `postal-pigeon keygen <file>`)")?;
    let hmac_file = settings
        .hmac_key_file
        .as_ref()
        .ok_or("PP_HMAC_KEY_FILE is required (create one with `postal-pigeon keygen <file>`)")?;
    // The key bytes are wiped from memory when these go out of scope.
    let seal = read_key_file(seal_file)?;
    let hmac = read_key_file(hmac_file)?;
    // One key must never do both jobs: a leak of the HMAC key (it signs the
    // challenges) would then open the sealed tokens.
    if seal.as_slice() == hmac.as_slice() {
        return Err("PP_SEAL_KEY_FILE and PP_HMAC_KEY_FILE hold the same key; make two".into());
    }
    let old = settings
        .seal_old_key_files
        .iter()
        .map(|p| read_key_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let old_refs: Vec<&[u8]> = old.iter().map(|k| k.as_slice()).collect();
    if old_refs.contains(&hmac.as_slice()) {
        return Err("an old seal key is the same as the HMAC key".into());
    }
    let keys = Keys::new(&hmac, &seal, &old_refs);

    let apns_settings = settings
        .apns
        .as_ref()
        .ok_or("PP_APNS_KEY_PATH, PP_APNS_KEY_ID and PP_APNS_TEAM_ID are required")?;
    if settings.apps.is_empty() {
        return Err("PP_APPS is required, for example PP_APPS=hedgerow=tools.hedgerow.app".into());
    }
    let clock = Clock::new();
    // The relay and the admin commands share one provider token through a file
    // in the runtime folder, since Apple limits how often a new one may be made.
    let apns = Apns::from_settings(apns_settings, settings.apns_urls.clone(), clock.clone())?
        .with_token_dir(settings.runtime_dir.join("postal-pigeon"));
    let db = Db::open(&settings.data_dir.join(DB_FILE))?;
    Ok(AppState::new(settings, db, keys, clock, apns))
}

/// Serves until SIGINT or SIGTERM.
pub async fn run(settings: Settings) -> Result<(), Box<dyn Error>> {
    settings.check_proxy_config()?;
    let bind = settings.bind;
    let public = settings.public_url.clone();
    let limits = settings.limits.clone();
    let state = build_state(settings)?;

    // Housekeeping once now (it also re-seals after a key change), then hourly.
    let today = state.clock.today();
    let registered = state
        .db
        .call(move |c| crate::db::count_instances_created_on(c, today))
        .await?;
    state.set_registrations_today(registered as u32);
    let first = state.clone();
    tokio::task::spawn_blocking(move || maintenance::run_once(&first)).await??;
    tokio::spawn(maintenance::run_forever(state.clone()));

    let listener = TcpListener::bind(bind).await?;
    tracing::info!(
        listen = %bind,
        public_url = public.as_deref().unwrap_or("-"),
        version = env!("CARGO_PKG_VERSION"),
        "started"
    );
    serve(listener, api::router(state), &limits, shutdown_signal()).await;
    tracing::info!("stopped");
    Ok(())
}

/// Accepts connections until `shutdown` completes, then lets the open ones
/// finish (for a few seconds).
///
/// This is `hyper` directly rather than `axum::serve`, which sets no timer and
/// so no header-read or idle timeout: a client that sends its request one byte
/// at a time, or nothing at all, would hold a connection (and a permit) forever.
/// Here a client has `header_read_timeout_secs` to send the headers of each
/// request, which also bounds how long a kept-alive connection may sit idle,
/// and at most `max_connections` connections are open at once.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: &Limits,
    shutdown: impl Future<Output = ()>,
) {
    let header_timeout = Duration::from_secs(limits.header_read_timeout_secs.max(1));
    let slots = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let mut shutdown = pin!(shutdown);

    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            p = slots.clone().acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(_) => {
                    // Out of file descriptors and the like: back off a moment.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let app = app.clone();
        let mut stop = stop_rx.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let mut req = req.map(Body::new);
                req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                app.clone().oneshot(req)
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service);
            let mut conn = pin!(conn);
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = stop.changed() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.as_mut()).await;
                }
            }
        });
        // Forget finished connections so the set doesn't grow.
        while tasks.try_join_next().is_some() {}
    }

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}
