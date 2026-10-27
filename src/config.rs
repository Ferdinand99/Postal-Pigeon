//! Configuration: environment variables with the `PP_` prefix (or flags), and
//! the validated settings the rest of the relay uses.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;

use crate::limits::Limits;
use crate::util::IpNet;

/// What a push may be (docs/design.md section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A visible notification with fixed text from the app.
    Alert,
    /// A silent "fetch now".
    Sync,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Alert => "alert",
            Kind::Sync => "sync",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "alert" => Some(Kind::Alert),
            "sync" => Some(Kind::Sync),
            _ => None,
        }
    }
}

/// An APNs environment. Tokens only work in the environment that issued them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Env {
    Production,
    Sandbox,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Production => "production",
            Env::Sandbox => "sandbox",
        }
    }

    pub fn parse(s: &str) -> Option<Env> {
        match s {
            "production" => Some(Env::Production),
            "sandbox" => Some(Env::Sandbox),
            _ => None,
        }
    }
}

/// One app the relay serves: its id, its bundle id (the APNs topic) and the
/// push kinds it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub id: String,
    pub bundle_id: String,
    pub kinds: Vec<Kind>,
}

impl AppConfig {
    /// Parses `id=bundle.id` or `id=bundle.id:alert+sync`.
    pub fn parse(s: &str) -> Result<AppConfig, String> {
        let (id, rest) = s
            .split_once('=')
            .ok_or_else(|| format!("app '{s}': expected id=bundle.id[:alert+sync]"))?;
        let (bundle, kinds) = match rest.split_once(':') {
            Some((b, k)) => (b, Some(k)),
            None => (rest, None),
        };
        let id = id.trim();
        let bundle = bundle.trim();
        if id.is_empty()
            || !id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(format!(
                "app id '{id}': use lower-case letters, digits and '-'"
            ));
        }
        if bundle.is_empty()
            || !bundle
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        {
            return Err(format!("bundle id '{bundle}' for app '{id}' is not valid"));
        }
        let kinds = match kinds {
            None => vec![Kind::Alert, Kind::Sync],
            Some(k) => {
                let mut v = Vec::new();
                for part in k.split('+') {
                    let kind = Kind::parse(part.trim())
                        .ok_or_else(|| format!("app '{id}': unknown kind '{part}'"))?;
                    if !v.contains(&kind) {
                        v.push(kind);
                    }
                }
                v
            }
        };
        Ok(AppConfig {
            id: id.to_string(),
            bundle_id: bundle.to_string(),
            kinds,
        })
    }
}

/// The APNs credentials of the relay's Apple developer team.
#[derive(Debug, Clone)]
pub struct ApnsSettings {
    /// The `.p8` key file.
    pub key_path: PathBuf,
    pub key_id: String,
    pub team_id: String,
}

/// Where to reach APNs.
#[derive(Debug, Clone)]
pub struct ApnsUrls {
    pub production: String,
    pub sandbox: String,
}

impl Default for ApnsUrls {
    fn default() -> Self {
        ApnsUrls {
            production: "https://api.push.apple.com".into(),
            sandbox: "https://api.sandbox.push.apple.com".into(),
        }
    }
}

/// Everything the relay runs on.
#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub public_url: Option<String>,
    pub apps: Vec<AppConfig>,
    pub environments: Vec<Env>,
    pub apns: Option<ApnsSettings>,
    pub apns_urls: ApnsUrls,
    pub trusted_proxies: Vec<IpNet>,
    pub limits: Limits,
    pub hmac_key_file: Option<PathBuf>,
    pub seal_key_file: Option<PathBuf>,
    pub seal_old_key_files: Vec<PathBuf>,
}

impl Settings {
    pub fn app(&self, id: &str) -> Option<&AppConfig> {
        self.apps.iter().find(|a| a.id == id)
    }

    pub fn env_allowed(&self, env: Env) -> bool {
        self.environments.contains(&env)
    }
}

/// The command line and environment (`PP_*`). Every setting has a variable.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Address to listen on (plain HTTP; TLS is the reverse proxy's job).
    #[arg(long, env = "PP_BIND", default_value = "127.0.0.1:3010", global = true)]
    pub bind: SocketAddr,

    /// Folder for the database.
    #[arg(long, env = "PP_DATA_DIR", default_value = "data", global = true)]
    pub data_dir: PathBuf,

    /// The relay's public address (https://...), for logs and the admin output.
    #[arg(long, env = "PP_PUBLIC_URL", global = true)]
    pub public_url: Option<String>,

    /// The `.p8` APNs key from the Apple developer account.
    #[arg(long, env = "PP_APNS_KEY_PATH", global = true)]
    pub apns_key_path: Option<PathBuf>,

    /// The key's id (`kid`).
    #[arg(long, env = "PP_APNS_KEY_ID", global = true)]
    pub apns_key_id: Option<String>,

    /// The Apple team id (`iss`).
    #[arg(long, env = "PP_APNS_TEAM_ID", global = true)]
    pub apns_team_id: Option<String>,

    /// APNs environments devices may register for: production, sandbox or both.
    #[arg(
        long,
        env = "PP_APNS_ENVIRONMENT",
        value_delimiter = ',',
        default_value = "production,sandbox",
        global = true
    )]
    pub apns_environment: Vec<String>,

    /// Apps the relay serves: id=bundle.id[:alert+sync], comma separated
    /// (for example hedgerow=tools.hedgerow.app).
    #[arg(long, env = "PP_APPS", value_delimiter = ',', global = true)]
    pub apps: Vec<String>,

    /// Proxies (addresses or CIDR networks) whose X-Forwarded-For is believed.
    #[arg(long, env = "PP_TRUSTED_PROXIES", value_delimiter = ',', global = true)]
    pub trusted_proxies: Vec<String>,

    /// File with the key that seals device tokens (64 hex characters).
    #[arg(long, env = "PP_SEAL_KEY_FILE", global = true)]
    pub seal_key_file: Option<PathBuf>,

    /// Files with older sealing keys, kept until tokens are re-sealed.
    #[arg(
        long,
        env = "PP_SEAL_OLD_KEY_FILES",
        value_delimiter = ',',
        global = true
    )]
    pub seal_old_key_files: Vec<PathBuf>,

    /// File with the HMAC key for challenges and token fingerprints.
    #[arg(long, env = "PP_HMAC_KEY_FILE", global = true)]
    pub hmac_key_file: Option<PathBuf>,

    /// JSON file that overrides any of the limits (see docs/api.md).
    #[arg(long, env = "PP_LIMITS_FILE", global = true)]
    pub limits_file: Option<PathBuf>,

    /// Staging and tests only: another APNs production address.
    #[arg(long, env = "PP_APNS_PRODUCTION_URL", hide = true, global = true)]
    pub apns_production_url: Option<String>,

    /// Staging and tests only: another APNs sandbox address.
    #[arg(long, env = "PP_APNS_SANDBOX_URL", hide = true, global = true)]
    pub apns_sandbox_url: Option<String>,
}

impl ConfigArgs {
    /// Validates the arguments into [`Settings`].
    pub fn into_settings(self) -> Result<Settings, String> {
        let mut environments = Vec::new();
        for e in &self.apns_environment {
            let env = Env::parse(e.trim()).ok_or_else(|| {
                format!("PP_APNS_ENVIRONMENT: '{e}' is not production or sandbox")
            })?;
            if !environments.contains(&env) {
                environments.push(env);
            }
        }
        if environments.is_empty() {
            return Err("PP_APNS_ENVIRONMENT needs production, sandbox or both".into());
        }

        let apps = self
            .apps
            .iter()
            .map(|a| AppConfig::parse(a))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, a) in apps.iter().enumerate() {
            if apps[..i].iter().any(|b| b.id == a.id) {
                return Err(format!("PP_APPS: app '{}' is listed twice", a.id));
            }
        }

        let mut trusted_proxies = Vec::new();
        for p in &self.trusted_proxies {
            trusted_proxies.push(IpNet::parse(p).ok_or_else(|| {
                format!("PP_TRUSTED_PROXIES: '{p}' is not an address or network")
            })?);
        }

        let apns = match (self.apns_key_path, self.apns_key_id, self.apns_team_id) {
            (Some(key_path), Some(key_id), Some(team_id)) => Some(ApnsSettings {
                key_path,
                key_id,
                team_id,
            }),
            (None, None, None) => None,
            _ => {
                return Err(
                    "PP_APNS_KEY_PATH, PP_APNS_KEY_ID and PP_APNS_TEAM_ID go together".into(),
                );
            }
        };

        let limits = match &self.limits_file {
            None => Limits::default(),
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("can't read {}: {e}", path.display()))?;
                let limits: Limits =
                    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
                limits.validate()?;
                limits
            }
        };

        if let Some(url) = &self.public_url
            && !(url.starts_with("https://") || url.starts_with("http://localhost"))
        {
            tracing::warn!("PP_PUBLIC_URL should be an https:// address");
        }

        let defaults = ApnsUrls::default();
        Ok(Settings {
            bind: self.bind,
            data_dir: self.data_dir,
            public_url: self.public_url,
            apps,
            environments,
            apns,
            apns_urls: ApnsUrls {
                production: self.apns_production_url.unwrap_or(defaults.production),
                sandbox: self.apns_sandbox_url.unwrap_or(defaults.sandbox),
            },
            trusted_proxies,
            limits,
            hmac_key_file: self.hmac_key_file,
            seal_key_file: self.seal_key_file,
            seal_old_key_files: self.seal_old_key_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apps() {
        let a = AppConfig::parse("hedgerow=tools.hedgerow.app").unwrap();
        assert_eq!(a.kinds, vec![Kind::Alert, Kind::Sync]);
        let f = AppConfig::parse("ferret=tools.hedgerow.ferret:sync").unwrap();
        assert_eq!(f.kinds, vec![Kind::Sync]);
        let both = AppConfig::parse("x=a.b:alert+sync+alert").unwrap();
        assert_eq!(both.kinds, vec![Kind::Alert, Kind::Sync]);
        assert!(AppConfig::parse("nope").is_err());
        assert!(AppConfig::parse("Bad=a.b").is_err());
        assert!(AppConfig::parse("x=a b").is_err());
        assert!(AppConfig::parse("x=a.b:loud").is_err());
    }
}
