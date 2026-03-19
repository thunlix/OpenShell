// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Syslog export for policy and guardrail events.
//!
//! Subscribes to the [`TracingLogBus`] global broadcast and forwards events to
//! a syslog collector in **CEF** (Common Event Format) over **TCP syslog**
//! (RFC 5425 octet-count framing), **TLS/TCP syslog** (RFC 5425 with TLS
//! transport per RFC 5425 §4), or **UDP syslog** (RFC 5424, datagram per
//! message).
//!
//! CEF is the native ingestion format for Palo Alto Networks XSIAM and
//! Cortex XSOAR.  Each `SandboxLogLine` is mapped to a CEF message using
//! standard extension keys (`dst`, `dpt`, `sproc`, `act`, `reason`, etc.)
//! derived from the structured fields emitted by the proxy and L7 relay.
//!
//! # Transport
//!
//! TLS/TCP (port 6514) is recommended for XSIAM in production — it provides
//! ordered, reliable, encrypted delivery.  Plain TCP (port 514) is available
//! for internal collector deployments where encryption is handled at the
//! network layer.  UDP is available as a fallback.
//!
//! # TLS
//!
//! Set [`SyslogTlsConfig`] on [`SyslogConfig`] to enable TLS.  By default the
//! collector certificate is verified against the Mozilla root CA bundle
//! (`webpki-roots`).  Set a custom CA path to verify against a private PKI,
//! or set `skip_verify = true` for self-signed certs in non-production
//! environments.
//!
//! # Reliability
//!
//! Delivery is **best-effort**.  If the connection is unavailable, events
//! received during the outage are dropped after one reconnect attempt per
//! event.  This avoids unbounded buffering while keeping the hot path
//! (tracing broadcast) non-blocking.  The exporter logs a warning for each
//! dropped event so operators can detect gaps.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{ServerName, UnixTime};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use openshell_core::proto::SandboxLogLine;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Syslog export configuration.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    /// Destination syslog collector address (host:port, e.g. `10.0.0.1:514`
    /// for plain TCP/UDP or `10.0.0.1:6514` for TLS).
    pub target: SocketAddr,
    /// Transport protocol.
    pub protocol: SyslogProtocol,
    /// Minimum log level to forward.  Events below this level are silently
    /// dropped before formatting, reducing noise in the SIEM.
    pub min_level: SyslogMinLevel,
    /// Hostname written into the RFC 5424 syslog header.
    /// Defaults to the system hostname; set explicitly in containerised
    /// deployments where the OS hostname is not meaningful.
    pub hostname: String,
    /// TLS configuration.  When `Some`, the TCP connection is wrapped in TLS
    /// (RFC 5425).  Ignored for UDP.
    pub tls: Option<SyslogTlsConfig>,
}

/// TLS configuration for syslog-over-TLS (RFC 5425).
#[derive(Debug, Clone)]
pub struct SyslogTlsConfig {
    /// SNI server name sent during the TLS handshake.  Required because
    /// [`SyslogConfig::target`] is an IP address and carries no hostname.
    /// Must match the CN or a SAN in the collector's certificate.
    pub server_name: String,
    /// Path to a PEM-encoded CA certificate used to verify the collector.
    /// When `None`, the Mozilla root CA bundle (`webpki-roots`) is used.
    pub ca_cert: Option<PathBuf>,
    /// Skip TLS certificate verification entirely.
    ///
    /// **Use only in non-production environments.**  When `true`, the
    /// connection is encrypted but the collector's identity is not verified,
    /// leaving it vulnerable to MITM attacks.
    pub skip_verify: bool,
}

/// Syslog transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogProtocol {
    /// Plain TCP with RFC 5425 octet-count framing.
    /// Wrap with [`SyslogTlsConfig`] to enable TLS (recommended for XSIAM).
    Tcp,
    /// UDP datagrams (RFC 5424).  Use when the collector does not accept TCP.
    Udp,
}

/// Minimum log level for syslog forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogMinLevel {
    Info,
    Warn,
    Error,
}

impl SyslogMinLevel {
    fn passes(self, level: &str) -> bool {
        match self {
            Self::Error => matches!(
                level.to_ascii_uppercase().as_str(),
                "ERROR"
            ),
            Self::Warn => matches!(
                level.to_ascii_uppercase().as_str(),
                "WARN" | "WARNING" | "ERROR"
            ),
            Self::Info => matches!(
                level.to_ascii_uppercase().as_str(),
                "INFO" | "WARN" | "WARNING" | "ERROR"
            ),
        }
    }
}

// ── Public entry point ─────────────────────────────────────────────────────────

/// Spawn the syslog exporter as a background task.
///
/// `rx` should come from [`TracingLogBus::subscribe_all`].  The task runs
/// until the channel is closed (i.e. the bus is dropped).
pub fn spawn_syslog_exporter(
    rx: broadcast::Receiver<SandboxLogLine>,
    config: SyslogConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_exporter(rx, config))
}

// ── Exporter loop ──────────────────────────────────────────────────────────────

async fn run_exporter(mut rx: broadcast::Receiver<SandboxLogLine>, config: SyslogConfig) {
    match config.protocol {
        SyslogProtocol::Tcp => run_tcp_exporter(&mut rx, &config).await,
        SyslogProtocol::Udp => run_udp_exporter(&mut rx, &config).await,
    }
}

// ── TCP/TLS connection abstraction ────────────────────────────────────────────

/// A connected syslog writer — either a plain TCP stream or a TLS-wrapped one.
///
/// Both variants implement the same write path so the event loop is shared.
enum Connection {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl Connection {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.write_all(buf).await,
            Self::Tls(s) => s.write_all(buf).await,
        }
    }
}

/// Open a TCP connection to `target`, optionally wrapping it in TLS.
async fn open_connection(
    target: SocketAddr,
    tls: Option<&SyslogTlsConfig>,
) -> Result<Connection, String> {
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let Some(tls_cfg) = tls else {
        return Ok(Connection::Plain(tcp));
    };

    let connector = build_tls_connector(tls_cfg)
        .map_err(|e| format!("TLS config error: {e}"))?;

    let server_name = ServerName::try_from(tls_cfg.server_name.as_str())
        .map_err(|e| format!("invalid TLS server name {:?}: {e}", tls_cfg.server_name))?
        .to_owned();

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    Ok(Connection::Tls(tls_stream))
}

/// Build a `TlsConnector` from the given [`SyslogTlsConfig`].
fn build_tls_connector(cfg: &SyslogTlsConfig) -> Result<tokio_rustls::TlsConnector, String> {
    let client_config = if cfg.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else if let Some(ca_path) = &cfg.ca_cert {
        let ca_file =
            std::fs::File::open(ca_path).map_err(|e| format!("open CA cert {ca_path:?}: {e}"))?;
        let mut reader = std::io::BufReader::new(ca_file);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| format!("read CA cert: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("add CA cert: {e}"))?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        // Use the Mozilla root CA bundle.
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

/// A TLS certificate verifier that accepts any certificate.
///
/// Used only when [`SyslogTlsConfig::skip_verify`] is `true`.  The connection
/// is still encrypted; only authentication is skipped.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── TCP transport ──────────────────────────────────────────────────────────────

async fn run_tcp_exporter(rx: &mut broadcast::Receiver<SandboxLogLine>, config: &SyslogConfig) {
    let mut conn: Option<Connection> = None;
    let mut backoff = Duration::from_secs(1);
    let tls_label = if config.tls.is_some() { "TLS" } else { "plain" };

    loop {
        // Ensure we have a live connection before waiting for the next event.
        if conn.is_none() {
            match open_connection(config.target, config.tls.as_ref()).await {
                Ok(c) => {
                    debug!(
                        target = %config.target,
                        tls = tls_label,
                        "syslog: TCP connected"
                    );
                    conn = Some(c);
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        target = %config.target,
                        tls = tls_label,
                        backoff_secs = backoff.as_secs(),
                        "syslog: connect failed"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            }
        }

        let log = match rx.recv().await {
            Ok(l) => l,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(dropped = n, "syslog: exporter lagged, events dropped");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("syslog: broadcast channel closed, exiting");
                break;
            }
        };

        if !config.min_level.passes(&log.level) {
            continue;
        }

        let msg = format_cef_syslog(&log, &config.hostname);
        // RFC 5425 octet-count framing: "<len> <msg>\n"
        let framed = format!("{} {}\n", msg.len(), msg);

        if let Err(e) = conn.as_mut().unwrap().write_all(framed.as_bytes()).await {
            warn!(
                error = %e,
                sandbox_id = %log.sandbox_id,
                tls = tls_label,
                "syslog: write failed, event dropped — will reconnect"
            );
            conn = None;
            // Reconnect happens at the top of the next iteration.
        }
    }
}

// ── UDP transport ──────────────────────────────────────────────────────────────

async fn run_udp_exporter(rx: &mut broadcast::Receiver<SandboxLogLine>, config: &SyslogConfig) {
    let bind: SocketAddr = "0.0.0.0:0".parse().expect("valid bind addr");
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "syslog: failed to bind UDP socket, exporter disabled");
            return;
        }
    };

    loop {
        let log = match rx.recv().await {
            Ok(l) => l,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(dropped = n, "syslog: exporter lagged, events dropped");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("syslog: broadcast channel closed, exiting");
                break;
            }
        };

        if !config.min_level.passes(&log.level) {
            continue;
        }

        let msg = format_cef_syslog(&log, &config.hostname);
        if let Err(e) = socket.send_to(msg.as_bytes(), config.target).await {
            warn!(
                error = %e,
                sandbox_id = %log.sandbox_id,
                "syslog: UDP send failed, event dropped"
            );
        }
    }
}

// ── CEF formatting ─────────────────────────────────────────────────────────────

/// Format a `SandboxLogLine` as a CEF message wrapped in an RFC 5424 syslog
/// header.
///
/// Output shape:
/// ```text
/// <PRI>1 <TIMESTAMP> <HOSTNAME> openshell-server - - - CEF:0|NVIDIA|OpenShell|<ver>|<sig>|<name>|<sev>|<ext>
/// ```
fn format_cef_syslog(log: &SandboxLogLine, hostname: &str) -> String {
    let version = openshell_core::VERSION;

    // Determine the policy action from available fields (priority order).
    let action = log
        .fields
        .get("action")
        .or_else(|| log.fields.get("l7_action"))
        .or_else(|| log.fields.get("l7_decision"))
        .map(String::as_str)
        .unwrap_or("");

    // CEF severity (0–10) and event class ID.
    let (cef_severity, sig_id) = match action {
        "deny" => (7u8, "POLICY_DENY"),
        "audit" => (5u8, "POLICY_AUDIT"),
        "allow" => (2u8, "POLICY_ALLOW"),
        _ => match log.level.to_ascii_uppercase().as_str() {
            "ERROR" => (8u8, "ERROR"),
            "WARN" | "WARNING" => (5u8, "WARN"),
            _ => (2u8, "LOG"),
        },
    };

    // Syslog PRI: facility 10 (security/authorization) × 8 + severity.
    let syslog_severity: u8 = match cef_severity {
        8..=10 => 3, // error
        6..=7 => 4,  // warning
        4..=5 => 5,  // notice
        _ => 6,      // informational
    };
    let pri = 10u8 * 8 + syslog_severity;

    let ts = format_rfc3339(log.timestamp_ms);
    let name = cef_escape(&log.message);

    // Build CEF extension key=value pairs.
    let ext = build_cef_extension(log);

    format!(
        "<{pri}>1 {ts} {hostname} openshell-server - - - \
         CEF:0|NVIDIA|OpenShell|{version}|{sig_id}|{name}|{cef_severity}|{ext}"
    )
}

/// Map `SandboxLogLine` fields to CEF extension key=value pairs.
fn build_cef_extension(log: &SandboxLogLine) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Always include sandbox_id as the device external ID.
    if !log.sandbox_id.is_empty() {
        parts.push(format!("deviceExternalId={}", cef_escape(&log.sandbox_id)));
    }

    // Map structured fields to CEF standard keys.
    // When multiple source fields map to the same CEF key, the first hit wins.
    let mappings: &[(&str, &str)] = &[
        ("dst_host", "dst"),
        ("host", "dst"),
        ("dst_port", "dpt"),
        ("port", "dpt"),
        ("binary", "sproc"),
        ("deny_reason", "reason"),
        ("l7_method", "requestMethod"),
        ("l7_path", "request"),
        ("l7_target", "request"),
        ("l7_protocol", "app"),
        ("l7_decision", "act"),
        ("l7_action", "act"),
        ("action", "act"),
    ];

    let mut used_cef_keys = HashSet::new();
    for (src, cef_key) in mappings {
        if used_cef_keys.contains(cef_key) {
            continue;
        }
        if let Some(val) = log.fields.get(*src) {
            parts.push(format!("{}={}", cef_key, cef_escape(val)));
            used_cef_keys.insert(*cef_key);
        }
    }

    // Custom string extensions for fields without a standard CEF key.
    if let Some(stage) = log.fields.get("denial_stage") {
        parts.push(format!("cs1Label=stage cs1={}", cef_escape(stage)));
    }
    if let Some(policy) = log.fields.get("policy") {
        parts.push(format!("cs2Label=policy cs2={}", cef_escape(policy)));
    }

    // Include the original event timestamp as `rt` (receipt time in epoch ms).
    if log.timestamp_ms > 0 {
        parts.push(format!("rt={}", log.timestamp_ms));
    }

    parts.join(" ")
}

/// Escape special characters in CEF extension values.
///
/// CEF requires `\`, `=`, `\n`, and `\r` to be escaped.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// ── Timestamp formatting ───────────────────────────────────────────────────────

/// Format an epoch-millisecond timestamp as an RFC 3339 string
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), required by RFC 5424.
///
/// Implemented without external crates by performing integer calendar
/// arithmetic.
fn format_rfc3339(ts_ms: i64) -> String {
    if ts_ms <= 0 {
        return "1970-01-01T00:00:00.000Z".to_string();
    }
    let secs = ts_ms as u64 / 1000;
    let ms = ts_ms as u64 % 1000;
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Convert days since Unix epoch (1970-01-01) to `(year, month, day)`.
///
/// Uses Howard Hinnant's `civil_from_days` algorithm — a standard, verified
/// implementation of proleptic Gregorian calendar arithmetic.
/// Reference: <https://howardhinnant.github.io/date_algorithms.html>
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // day of era [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year prime [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_log(level: &str, message: &str, fields: &[(&str, &str)]) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-test".to_string(),
            timestamp_ms: 1_742_300_000_000, // 2025-03-18T...
            level: level.to_string(),
            target: "openshell_sandbox::proxy".to_string(),
            message: message.to_string(),
            source: "sandbox".to_string(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn cef_deny_event_contains_expected_fields() {
        let log = make_log(
            "INFO",
            "CONNECT",
            &[
                ("action", "deny"),
                ("dst_host", "evil.example.com"),
                ("dst_port", "443"),
                ("binary", "/usr/bin/curl"),
                ("deny_reason", "no matching policy"),
                ("denial_stage", "connect"),
            ],
        );
        let msg = format_cef_syslog(&log, "gateway-1");

        assert!(msg.contains("CEF:0|NVIDIA|OpenShell|"), "missing CEF header");
        assert!(msg.contains("POLICY_DENY"), "wrong sig_id");
        assert!(msg.contains("dst=evil.example.com"), "missing dst");
        assert!(msg.contains("dpt=443"), "missing dpt");
        assert!(msg.contains("sproc=/usr/bin/curl"), "missing sproc");
        assert!(msg.contains("act=deny"), "missing act");
        assert!(
            msg.contains("reason=no matching policy"),
            "missing reason"
        );
        assert!(msg.contains("cs1Label=stage"), "missing stage label");
        assert!(msg.contains("cs1=connect"), "missing stage value");
        assert!(msg.contains("deviceExternalId=sb-test"), "missing sandbox id");
    }

    #[test]
    fn cef_l7_audit_event() {
        let log = make_log(
            "INFO",
            "L7_REQUEST",
            &[
                ("l7_decision", "audit"),
                ("l7_method", "POST"),
                ("l7_target", "/v1/chat/completions"),
                ("l7_protocol", "openai_chat_completions"),
                ("dst_host", "api.openai.com"),
            ],
        );
        let msg = format_cef_syslog(&log, "gw");
        assert!(msg.contains("POLICY_AUDIT"), "wrong sig_id");
        assert!(msg.contains("act=audit"), "missing act");
        assert!(msg.contains("requestMethod=POST"), "missing method");
        assert!(msg.contains("request=/v1/chat/completions"), "missing path");
        assert!(
            msg.contains("app=openai_chat_completions"),
            "missing protocol"
        );
    }

    #[test]
    fn cef_escape_special_chars() {
        assert_eq!(cef_escape("a=b"), "a\\=b");
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
        assert_eq!(cef_escape("a\nb"), "a\\nb");
        assert_eq!(cef_escape("plain"), "plain");
    }

    #[test]
    fn timestamp_known_epoch() {
        // 2026-03-18T00:00:00.000Z
        // Days since 1970-01-01:  56 years * 365 + leap days
        // Verified: 2026-03-18 is day 20530 since Unix epoch
        // (confirmed via: python3 -c "from datetime import date; print((date(2026,3,18)-date(1970,1,1)).days)")
        let ms = 20530u64 * 86400 * 1000;
        let ts = format_rfc3339(ms as i64);
        assert_eq!(ts, "2026-03-18T00:00:00.000Z");
    }

    #[test]
    fn timestamp_known_with_time_and_ms() {
        // 2026-03-18T12:34:56.789Z
        let base = 20530u64 * 86400 * 1000;
        let time_ms = (12 * 3600 + 34 * 60 + 56) * 1000 + 789;
        let ts = format_rfc3339((base + time_ms) as i64);
        assert_eq!(ts, "2026-03-18T12:34:56.789Z");
    }

    #[test]
    fn timestamp_zero() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn min_level_passes_correctly() {
        assert!(SyslogMinLevel::Info.passes("INFO"));
        assert!(SyslogMinLevel::Info.passes("WARN"));
        assert!(SyslogMinLevel::Info.passes("ERROR"));
        assert!(!SyslogMinLevel::Info.passes("DEBUG"));

        assert!(!SyslogMinLevel::Warn.passes("INFO"));
        assert!(SyslogMinLevel::Warn.passes("WARN"));
        assert!(SyslogMinLevel::Warn.passes("ERROR"));

        assert!(!SyslogMinLevel::Error.passes("WARN"));
        assert!(SyslogMinLevel::Error.passes("ERROR"));
    }

    #[test]
    fn syslog_header_format() {
        let log = make_log("INFO", "test", &[]);
        let msg = format_cef_syslog(&log, "my-host");
        // Must start with <PRI>1 and contain the hostname
        assert!(msg.starts_with('<'), "missing PRI open bracket");
        assert!(msg.contains(">1 "), "missing RFC5424 version");
        assert!(msg.contains(" my-host "), "missing hostname");
        assert!(msg.contains(" openshell-server "), "missing app-name");
    }
}
