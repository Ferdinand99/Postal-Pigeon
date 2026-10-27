//! Which log lines are written.
//!
//! `RUST_LOG` only sets the level of the relay's own lines. Every other crate
//! (the HTTP stack, TLS, the runtime) stays at `warn` whatever it says, because
//! at `debug` and `trace` those crates log request details that the relay
//! promises never to write: device tokens in request paths and the provider
//! token in headers.

use tracing_subscriber::EnvFilter;

const LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];

fn level(s: &str) -> Option<&'static str> {
    let s = s.trim().to_ascii_lowercase();
    LEVELS.iter().find(|l| **l == s).copied()
}

/// The level for the relay's own lines from a `RUST_LOG` value: a bare level
/// (`debug`) or a `postal_pigeon=level` directive. Anything else is ignored.
pub fn own_level(rust_log: Option<&str>) -> &'static str {
    let Some(text) = rust_log else {
        return "info";
    };
    let mut found = None;
    for directive in text.split(',') {
        match directive.split_once('=') {
            None => found = level(directive).or(found),
            Some((target, lvl)) if target.trim() == "postal_pigeon" => {
                found = level(lvl).or(found);
            }
            Some(_) => {}
        }
    }
    found.unwrap_or("info")
}

/// The filter to install: the relay at its level, everything else at `warn`.
pub fn filter(rust_log: Option<&str>) -> EnvFilter {
    EnvFilter::new(format!("warn,postal_pigeon={}", own_level(rust_log)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_relays_own_level_can_be_raised() {
        assert_eq!(own_level(None), "info");
        assert_eq!(own_level(Some("debug")), "debug");
        assert_eq!(own_level(Some("TRACE")), "trace");
        assert_eq!(own_level(Some("warn,hyper=trace,h2=trace")), "warn");
        assert_eq!(
            own_level(Some("info,postal_pigeon=trace,reqwest=trace")),
            "trace"
        );
        assert_eq!(own_level(Some("hyper=trace")), "info");
        assert_eq!(own_level(Some("nonsense")), "info");
    }
}
