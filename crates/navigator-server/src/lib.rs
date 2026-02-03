//! Navigator Server library.
//!
//! This crate provides the server implementation for Navigator, including:
//! - gRPC service implementation
//! - HTTP health endpoints
//! - Protocol multiplexing (gRPC + HTTP on same port)
//! - Optional TLS support

mod grpc;
mod http;
mod multiplex;
mod persistence;
mod tls;

use navigator_core::{Config, Error, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{error, info};

pub use grpc::NavigatorService;
pub use http::health_router;
pub use multiplex::MultiplexService;
use persistence::Store;
pub use tls::TlsAcceptor;

/// Server state shared across handlers.
#[derive(Debug)]
pub struct ServerState {
    /// Server start time for uptime calculation.
    pub start_time: Instant,

    /// Server configuration.
    pub config: Config,

    /// Persistence store.
    pub store: Arc<Store>,
}

impl ServerState {
    /// Create new server state.
    #[must_use]
    pub fn new(config: Config, store: Arc<Store>) -> Self {
        Self {
            start_time: Instant::now(),
            config,
            store,
        }
    }

    /// Get server uptime in seconds.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

/// Run the Navigator server.
///
/// This starts a multiplexed gRPC/HTTP server on the configured bind address.
///
/// # Errors
///
/// Returns an error if the server fails to start or encounters a fatal error.
pub async fn run_server(config: Config) -> Result<()> {
    let database_url = config.database_url.trim();
    if database_url.is_empty() {
        return Err(Error::config("database_url is required"));
    }

    let store = Store::connect(database_url).await?;
    let state = Arc::new(ServerState::new(config.clone(), Arc::new(store)));

    // Create the multiplexed service
    let service = MultiplexService::new(state.clone());

    // Bind the TCP listener
    let listener = TcpListener::bind(config.bind_address)
        .await
        .map_err(|e| Error::transport(format!("failed to bind to {}: {e}", config.bind_address)))?;

    info!(address = %config.bind_address, "Server listening");

    // Accept connections
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
                continue;
            }
        };

        let service = service.clone();

        tokio::spawn(async move {
            if let Err(e) = service.serve(stream).await {
                error!(error = %e, client = %addr, "Connection error");
            }
        });
    }
}
