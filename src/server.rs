//! Building the application and serving it.

use std::error::Error;
use std::net::SocketAddr;

use crate::api;
use crate::apns::Apns;
use crate::clock::Clock;
use crate::config::Settings;
use crate::crypto::{Keys, read_key_file};
use crate::db::Db;
use crate::maintenance;
use crate::state::AppState;

/// The database file inside the data directory.
pub const DB_FILE: &str = "pigeon.sqlite";

/// Opens the database, loads the keys and the APNs key.
pub fn build_state(settings: Settings) -> Result<AppState, Box<dyn Error>> {
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
    let seal = read_key_file(seal_file)?;
    let hmac = read_key_file(hmac_file)?;
    let old = settings
        .seal_old_key_files
        .iter()
        .map(|p| read_key_file(p))
        .collect::<Result<Vec<_>, _>>()?;
    let keys = Keys::new(&hmac, &seal, &old);

    let apns_settings = settings
        .apns
        .as_ref()
        .ok_or("PP_APNS_KEY_PATH, PP_APNS_KEY_ID and PP_APNS_TEAM_ID are required")?;
    if settings.apps.is_empty() {
        return Err("PP_APPS is required, for example PP_APPS=hedgerow=tools.hedgerow.app".into());
    }
    let clock = Clock::new();
    let apns = Apns::from_settings(apns_settings, settings.apns_urls.clone(), clock.clone())?;
    let db = Db::open(&settings.data_dir.join(DB_FILE))?;
    Ok(AppState::new(settings, db, keys, clock, apns))
}

/// Serves until SIGINT or SIGTERM.
pub async fn run(settings: Settings) -> Result<(), Box<dyn Error>> {
    let bind = settings.bind;
    let public = settings.public_url.clone();
    let state = build_state(settings)?;

    // Housekeeping once now (it also re-seals after a key change), then hourly.
    let first = state.clone();
    tokio::task::spawn_blocking(move || maintenance::run_once(&first)).await??;
    tokio::spawn(maintenance::run_forever(state.clone()));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        listen = %bind,
        public_url = public.as_deref().unwrap_or("-"),
        version = env!("CARGO_PKG_VERSION"),
        "started"
    );
    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    tracing::info!("stopped");
    Ok(())
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
