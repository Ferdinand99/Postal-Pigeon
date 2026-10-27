//! Postal Pigeon, the Hedgerow push relay: a content-free doorbell between
//! self-hosted servers and iOS push. See `docs/design.md` for the design and
//! `docs/api.md` for the API.

pub mod admin;
pub mod api;
pub mod apns;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod db;
pub mod limits;
pub mod maintenance;
pub mod pow;
pub mod server;
pub mod state;
pub mod util;
