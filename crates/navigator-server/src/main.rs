//! Navigator Server - gRPC/HTTP server with protocol multiplexing.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use navigator_server::{run_server, tracing_bus::TracingLogBus};

/// Navigator Server - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(name = "navigator-server")]
#[command(about = "Navigator gRPC/HTTP server", long_about = None)]
struct Args {
    /// Port to bind the server to (all interfaces).
    #[arg(long, default_value_t = 8080, env = "NAVIGATOR_SERVER_PORT")]
    port: u16,

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

    /// Kubernetes namespace for sandboxes.
    #[arg(long, env = "NAVIGATOR_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[arg(long, env = "NAVIGATOR_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    /// gRPC endpoint for sandboxes to callback to Navigator.
    /// This should be reachable from within the Kubernetes cluster.
    #[arg(long, env = "NAVIGATOR_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    let args = Args::parse();

    // Initialize tracing
    let tracing_log_bus = TracingLogBus::new();
    tracing_log_bus.install_subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
    );

    // Build configuration
    let bind = SocketAddr::from(([0, 0, 0, 0], args.port));

    let mut config = navigator_core::Config::default()
        .with_bind_address(bind)
        .with_log_level(&args.log_level);

    if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
        config = config.with_tls(cert, key);
    }

    config = config
        .with_database_url(args.db_url)
        .with_sandbox_namespace(args.sandbox_namespace);

    if let Some(image) = args.sandbox_image {
        config = config.with_sandbox_image(image);
    }

    if let Some(endpoint) = args.grpc_endpoint {
        config = config.with_grpc_endpoint(endpoint);
    }

    info!(bind = %config.bind_address, "Starting Navigator server");

    run_server(config, tracing_log_bus).await.into_diagnostic()
}
