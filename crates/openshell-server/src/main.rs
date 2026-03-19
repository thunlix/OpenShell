// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Server - gRPC/HTTP server with protocol multiplexing.

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_server::{
    run_server,
    syslog_export::{SyslogConfig, SyslogMinLevel, SyslogProtocol, SyslogTlsConfig},
    tracing_bus::TracingLogBus,
};

/// `OpenShell` Server - gRPC and HTTP server with protocol multiplexing.
#[derive(Parser, Debug)]
#[command(name = "openshell-server")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell gRPC/HTTP server", long_about = None)]
struct Args {
    /// Port to bind the server to (all interfaces).
    #[arg(long, default_value_t = 8080, env = "OPENSHELL_SERVER_PORT")]
    port: u16,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,

    /// Path to TLS certificate file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (required unless --disable-tls).
    #[arg(long, env = "OPENSHELL_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Path to CA certificate for client certificate verification (mTLS).
    #[arg(long, env = "OPENSHELL_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Database URL for persistence.
    #[arg(long, env = "OPENSHELL_DB_URL", required = true)]
    db_url: String,

    /// Kubernetes namespace for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    /// Kubernetes imagePullPolicy for sandbox pods (Always, IfNotPresent, Never).
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY")]
    sandbox_image_pull_policy: Option<String>,

    /// gRPC endpoint for sandboxes to callback to `OpenShell`.
    /// This should be reachable from within the Kubernetes cluster.
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    /// Public host for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_HOST", default_value = "127.0.0.1")]
    ssh_gateway_host: String,

    /// Public port for the SSH gateway.
    #[arg(long, env = "OPENSHELL_SSH_GATEWAY_PORT", default_value_t = 8080)]
    ssh_gateway_port: u16,

    /// HTTP path for SSH CONNECT/upgrade.
    #[arg(
        long,
        env = "OPENSHELL_SSH_CONNECT_PATH",
        default_value = "/connect/ssh"
    )]
    ssh_connect_path: String,

    /// SSH port inside sandbox pods.
    #[arg(long, env = "OPENSHELL_SANDBOX_SSH_PORT", default_value_t = 2222)]
    sandbox_ssh_port: u16,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: Option<String>,

    /// Allowed clock skew in seconds for SSH handshake.
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SKEW_SECS", default_value_t = 300)]
    ssh_handshake_skew_secs: u64,

    /// Kubernetes secret name containing client TLS materials for sandbox pods.
    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    /// Host gateway IP for sandbox pod hostAliases.
    /// When set, sandbox pods get hostAliases entries mapping
    /// host.docker.internal and host.openshell.internal to this IP.
    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,

    /// Disable TLS entirely — listen on plaintext HTTP.
    /// Use this when the gateway sits behind a reverse proxy or tunnel
    /// (e.g. Cloudflare Tunnel) that terminates TLS at the edge.
    #[arg(long, env = "OPENSHELL_DISABLE_TLS")]
    disable_tls: bool,

    /// Disable gateway authentication (mTLS client certificate requirement).
    /// When set, the TLS handshake accepts connections without a client
    /// certificate. Ignored when --disable-tls is set.
    #[arg(long, env = "OPENSHELL_DISABLE_GATEWAY_AUTH")]
    disable_gateway_auth: bool,

    /// Syslog collector address for policy event forwarding (host:port).
    ///
    /// When set, policy denial and L7 inspection events are forwarded to this
    /// address in CEF format over TCP or UDP syslog.  Compatible with Palo
    /// Alto Networks XSIAM and any RFC 5424-compliant collector.
    ///
    /// Example: `10.0.0.1:514`
    #[arg(long, env = "OPENSHELL_SYSLOG_TARGET")]
    syslog_target: Option<std::net::SocketAddr>,

    /// Syslog transport protocol: `tcp` (default) or `udp`.
    ///
    /// TCP uses RFC 5425 octet-count framing; UDP sends one datagram per
    /// message.  TCP is recommended for XSIAM.
    #[arg(long, env = "OPENSHELL_SYSLOG_PROTOCOL", default_value = "tcp")]
    syslog_protocol: String,

    /// Minimum log level to forward to syslog: `info` (default), `warn`, or `error`.
    ///
    /// Set to `warn` or `error` to reduce volume; set to `info` to forward
    /// all policy allow/deny/audit decisions.
    #[arg(long, env = "OPENSHELL_SYSLOG_LEVEL", default_value = "info")]
    syslog_level: String,

    /// Hostname reported in syslog messages.
    ///
    /// Defaults to the OS hostname.  Set explicitly in containerised
    /// deployments where the pod hostname is not meaningful.
    #[arg(long, env = "OPENSHELL_SYSLOG_HOSTNAME")]
    syslog_hostname: Option<String>,

    /// Enable TLS for syslog TCP transport (RFC 5425).
    ///
    /// When set, the TCP connection to --syslog-target is wrapped in TLS.
    /// Requires --syslog-tls-server-name.  Ignored when --syslog-protocol=udp.
    #[arg(long, env = "OPENSHELL_SYSLOG_TLS")]
    syslog_tls: bool,

    /// SNI server name for syslog TLS handshake.
    ///
    /// Required when --syslog-tls is set.  Must match the CN or a SAN in the
    /// collector's certificate (e.g. `syslog.xsiam.example.com`).
    #[arg(long, env = "OPENSHELL_SYSLOG_TLS_SERVER_NAME")]
    syslog_tls_server_name: Option<String>,

    /// Path to a PEM-encoded CA certificate for verifying the syslog collector.
    ///
    /// When omitted, the Mozilla root CA bundle is used.  Set this when the
    /// XSIAM collector uses a certificate signed by a private/internal CA.
    #[arg(long, env = "OPENSHELL_SYSLOG_TLS_CA")]
    syslog_tls_ca: Option<std::path::PathBuf>,

    /// Skip TLS certificate verification for the syslog collector.
    ///
    /// The connection is still encrypted.  Use only in non-production
    /// environments with self-signed certificates.
    #[arg(long, env = "OPENSHELL_SYSLOG_TLS_SKIP_VERIFY")]
    syslog_tls_skip_verify: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
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

    let tls = if args.disable_tls {
        None
    } else {
        let cert_path = args.tls_cert.ok_or_else(|| {
            miette::miette!(
                "--tls-cert is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        let key_path = args.tls_key.ok_or_else(|| {
            miette::miette!("--tls-key is required when TLS is enabled (use --disable-tls to skip)")
        })?;
        let client_ca_path = args.tls_client_ca.ok_or_else(|| {
            miette::miette!(
                "--tls-client-ca is required when TLS is enabled (use --disable-tls to skip)"
            )
        })?;
        Some(openshell_core::TlsConfig {
            cert_path,
            key_path,
            client_ca_path,
            allow_unauthenticated: args.disable_gateway_auth,
        })
    };

    let mut config = openshell_core::Config::new(tls)
        .with_bind_address(bind)
        .with_log_level(&args.log_level);

    config = config
        .with_database_url(args.db_url)
        .with_sandbox_namespace(args.sandbox_namespace)
        .with_ssh_gateway_host(args.ssh_gateway_host)
        .with_ssh_gateway_port(args.ssh_gateway_port)
        .with_ssh_connect_path(args.ssh_connect_path)
        .with_sandbox_ssh_port(args.sandbox_ssh_port)
        .with_ssh_handshake_skew_secs(args.ssh_handshake_skew_secs);

    if let Some(image) = args.sandbox_image {
        config = config.with_sandbox_image(image);
    }

    if let Some(policy) = args.sandbox_image_pull_policy {
        config = config.with_sandbox_image_pull_policy(policy);
    }

    if let Some(endpoint) = args.grpc_endpoint {
        config = config.with_grpc_endpoint(endpoint);
    }

    if let Some(secret) = args.ssh_handshake_secret {
        config = config.with_ssh_handshake_secret(secret);
    }

    if let Some(name) = args.client_tls_secret_name {
        config = config.with_client_tls_secret_name(name);
    }

    if let Some(ip) = args.host_gateway_ip {
        config = config.with_host_gateway_ip(ip);
    }

    if args.disable_tls {
        info!("TLS disabled — listening on plaintext HTTP");
    } else if args.disable_gateway_auth {
        info!("Gateway auth disabled — accepting connections without client certificates");
    }

    // Syslog exporter — optional, enabled only when --syslog-target is set.
    if let Some(syslog_target) = args.syslog_target {
        let protocol = match args.syslog_protocol.to_ascii_lowercase().as_str() {
            "udp" => SyslogProtocol::Udp,
            _ => SyslogProtocol::Tcp,
        };
        let min_level = match args.syslog_level.to_ascii_lowercase().as_str() {
            "error" => SyslogMinLevel::Error,
            "warn" | "warning" => SyslogMinLevel::Warn,
            _ => SyslogMinLevel::Info,
        };
        let hostname = args
            .syslog_hostname
            .or_else(|| hostname::get().ok()?.into_string().ok())
            .unwrap_or_else(|| "openshell-server".to_string());

        // Build TLS config if --syslog-tls was requested.
        let tls = if args.syslog_tls {
            let server_name = args.syslog_tls_server_name.ok_or_else(|| {
                miette::miette!(
                    "--syslog-tls-server-name is required when --syslog-tls is set"
                )
            })?;
            Some(SyslogTlsConfig {
                server_name,
                ca_cert: args.syslog_tls_ca,
                skip_verify: args.syslog_tls_skip_verify,
            })
        } else {
            None
        };

        let tls_enabled = tls.is_some();
        let syslog_cfg = SyslogConfig {
            target: syslog_target,
            protocol,
            min_level,
            hostname: hostname.clone(),
            tls,
        };

        let rx = tracing_log_bus.subscribe_all();
        openshell_server::syslog_export::spawn_syslog_exporter(rx, syslog_cfg);
        info!(
            target = %syslog_target,
            protocol = %args.syslog_protocol,
            level = %args.syslog_level,
            hostname = %hostname,
            tls = tls_enabled,
            "Syslog export enabled"
        );
    }

    info!(bind = %config.bind_address, "Starting OpenShell server");

    run_server(config, tracing_log_bus).await.into_diagnostic()
}
