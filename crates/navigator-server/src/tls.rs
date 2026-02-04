//! TLS support using tokio-rustls.

use navigator_core::{Error, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// TLS acceptor for wrapping connections.
#[derive(Clone)]
pub struct TlsAcceptor {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor from certificate and key files.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or key files cannot be read or parsed.
    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::tls(format!("failed to create TLS config: {e}")))?;

        config
            .alpn_protocols
            .extend([b"h2".to_vec(), b"http/1.1".to_vec()]);

        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        })
    }

    /// Get the inner tokio-rustls acceptor.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn inner(&self) -> &tokio_rustls::TlsAcceptor {
        &self.acceptor
    }
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).map_err(|e| Error::tls(format!("failed to open cert file: {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::tls(format!("failed to parse certificates: {e}")))?;

    if certs.is_empty() {
        return Err(Error::tls("no certificates found in file"));
    }

    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| Error::tls(format!("failed to open key file: {e}")))?;
    let mut reader = BufReader::new(file);

    loop {
        let item = rustls_pemfile::read_one(&mut reader)
            .map_err(|e| Error::tls(format!("failed to parse key file: {e}")))?;

        match item {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => {}
        }
    }

    Err(Error::tls("no private key found in file"))
}
