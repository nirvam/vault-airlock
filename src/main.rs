mod api;
mod hooks;
mod io_util;
mod vault;

use anyhow::{Context, Result};
use api::{AppState, UdsConnectInfo};
use axum::{
    routing::{get, post},
    Router,
};
use clap::{Parser, Subcommand};
use dialoguer::Password;
use hooks::{FeishuPostHook, HookRegistry};
use io_util::HttpRequest;
use std::{fs, path::PathBuf, sync::Arc};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "vault-airlock", author, version, about = "Vault-Airlock: Secure credential relay for isolated agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the vault daemon
    Serve {
        /// Path to the .kdbx file
        #[arg(short, long, env = "KDBX_PATH")]
        kdbx: PathBuf,

        /// Path to the Unix Domain Socket
        #[arg(short, long, default_value = "/tmp/kdbx.sock", env = "SOCKET_PATH")]
        socket: PathBuf,

        /// Feishu Webhook URL (optional)
        #[arg(long, env = "FEISHU_WEBHOOK")]
        feishu_webhook: Option<String>,
    },
    /// Unlock the vault
    Unlock {
        /// Path to the Unix Domain Socket
        #[arg(short, long, default_value = "/tmp/kdbx.sock", env = "SOCKET_PATH")]
        socket: PathBuf,
    },
    /// Lock the vault
    Lock {
        /// Path to the Unix Domain Socket
        #[arg(short, long, default_value = "/tmp/kdbx.sock", env = "SOCKET_PATH")]
        socket: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { kdbx, socket, feishu_webhook } => {
            run_serve(kdbx, socket, feishu_webhook).await
        }
        Commands::Unlock { socket } => run_unlock(socket).await,
        Commands::Lock { socket } => run_lock(socket).await,
    }
}

async fn run_serve(kdbx: PathBuf, socket: PathBuf, feishu_webhook: Option<String>) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(false)
        .compact()
        .init();

    if !kdbx.exists() {
        anyhow::bail!("KDBX file not found: {}", kdbx.display());
    }

    let mut hooks = HookRegistry::new();
    if let Some(webhook) = feishu_webhook {
        info!("Registering Feishu notification hook.");
        hooks.add_post_hook(Arc::new(FeishuPostHook { webhook_url: webhook }));
    }

    let state = Arc::new(AppState {
        vault: RwLock::new(None),
        hooks,
        kdbx_path: kdbx.clone(),
    });

    let app = Router::new()
        .route("/health", get(api::health))
        .route("/vault/unlock", post(api::unlock))
        .route("/vault/lock", post(api::lock))
        .route("/vault/tree", get(api::get_tree))
        .route("/vault/entry/{uuid}", get(api::get_entry))
        .route("/vault/search", post(api::search))
        .with_state(state)
        .into_make_service_with_connect_info::<UdsConnectInfo>();

    if socket.exists() {
        info!("Removing existing socket file: {}", socket.display());
        fs::remove_file(&socket)?;
    }

    let listener = UnixListener::bind(&socket).context("Failed to bind socket")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    }

    info!("Daemon started. KDBX: {}", kdbx.display());
    info!("Listening on {}...", socket.display());

    axum::serve(listener, app).await.context("Server error")
}

async fn run_unlock(socket: PathBuf) -> Result<()> {
    let password = Password::new()
        .with_prompt("Enter vault password")
        .interact()
        .context("Failed to read password")?;

    let payload = serde_json::json!({ "password": password });
    let body = serde_json::to_string(&payload)?;

    let mut stream = UnixStream::connect(&socket).await
        .context(format!("Failed to connect to daemon at {}", socket.display()))?;

    let request = HttpRequest::post("/vault/unlock", &body);
    request.send(&mut stream).await?;

    println!("Vault unlocked successfully.");
    Ok(())
}

async fn run_lock(socket: PathBuf) -> Result<()> {
    let mut stream = UnixStream::connect(&socket).await
        .context(format!("Failed to connect to daemon at {}", socket.display()))?;

    let request = HttpRequest::post("/vault/lock", "");
    request.send(&mut stream).await?;

    println!("Vault locked.");
    Ok(())
}
