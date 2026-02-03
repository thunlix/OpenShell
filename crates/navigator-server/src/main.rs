//! Navigator Server - gRPC/HTTP server with protocol multiplexing.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use navigator_server::run_server;

/// Navigator Server - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(name = "navigator-server")]
#[command(about = "Navigator gRPC/HTTP server", long_about = None)]
struct Args {
    /// Address to bind the server to.
    #[arg(long, short, default_value = "127.0.0.1:50051", env = "NAVIGATOR_BIND")]
    bind: SocketAddr,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "NAVIGATOR_LOG_LEVEL")]
    log_level: String,

    /// Path to TLS certificate file.
    #[arg(long, env = "NAVIGATOR_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file.
    #[arg(long, env = "NAVIGATOR_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Database URL for persistence.
    #[arg(long, env = "NAVIGATOR_DB_URL", required = true)]
    db_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    // Build configuration
    let mut config = navigator_core::Config::default()
        .with_bind_address(args.bind)
        .with_log_level(&args.log_level);

    if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
        config = config.with_tls(cert, key);
    }

    config = config.with_database_url(args.db_url);

    info!(bind = %config.bind_address, "Starting Navigator server");

    run_server(config).await.into_diagnostic()
}
