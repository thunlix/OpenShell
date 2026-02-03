//! Configuration management for Navigator components.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to bind the server to.
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// TLS configuration.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Database URL for persistence.
    pub database_url: String,
}

/// TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,

    /// Path to the TLS private key file.
    pub key_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            log_level: default_log_level(),
            tls: None,
            database_url: String::new(),
        }
    }
}

fn default_bind_address() -> SocketAddr {
    "127.0.0.1:50051".parse().expect("valid default address")
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Create a new configuration with the given bind address.
    #[must_use]
    pub const fn with_bind_address(mut self, addr: SocketAddr) -> Self {
        self.bind_address = addr;
        self
    }

    /// Create a new configuration with the given log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Create a new configuration with TLS enabled.
    #[must_use]
    pub fn with_tls(mut self, cert_path: PathBuf, key_path: PathBuf) -> Self {
        self.tls = Some(TlsConfig {
            cert_path,
            key_path,
        });
        self
    }

    /// Create a new configuration with a database URL.
    #[must_use]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = url.into();
        self
    }
}
