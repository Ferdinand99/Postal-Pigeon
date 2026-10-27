//! `postal-pigeon`: the Hedgerow push relay. `postal-pigeon --help` lists the
//! commands and the `PP_` environment variables.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use postal_pigeon::admin::{self, AdminCommand};
use postal_pigeon::config::ConfigArgs;
use postal_pigeon::{crypto, server};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "postal-pigeon", version, about = "The Hedgerow push relay")]
struct Cli {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay.
    Serve,
    /// Administer a running or stopped relay (run inside the container).
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Write a new random key file (mode 0600) for PP_SEAL_KEY_FILE or PP_HMAC_KEY_FILE.
    Keygen {
        /// The file to create; it must not exist.
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Colours only on a terminal: `docker logs` gets plain text.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    // Every TLS stack in the binary uses rustls; pin its crypto provider so a
    // dependency enabling a second one can't make rustls panic at runtime.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    if let Err(err) = run(cli).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if let Command::Keygen { path } = &cli.command {
        return keygen(path);
    }
    let settings = cli.config.into_settings()?;
    match cli.command {
        Command::Serve => server::run(settings).await,
        Command::Admin(cmd) => {
            let state = server::build_state(settings)?;
            print!("{}", admin::run(&state, cmd).await?);
            Ok(())
        }
        Command::Keygen { .. } => unreachable!("handled above"),
    }
}

fn keygen(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    writeln!(file, "{}", crypto::generate_key_hex())?;
    println!("wrote {}", path.display());
    Ok(())
}
