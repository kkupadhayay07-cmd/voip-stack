//! TLS plumbing for the daemon: a self-signed certificate generated at
//! startup (the same OpenSSL backend the `dtls` crate uses) plus server
//! acceptor and (verification-relaxed) client connector helpers.

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::{X509, X509NameBuilder};
use std::pin::Pin;
use tokio::net::TcpStream;

/// A generated identity: cert + private key, kept alive for the process.
pub struct TlsIdentity {
    pub cert: X509,
    pub key: PKey<Private>,
}

impl TlsIdentity {
    /// Generates a fresh self-signed RSA-2048 certificate (CN = `cn`).
    pub fn generate(cn: &str) -> Result<Self, String> {
        let rsa = Rsa::generate(2048).map_err(|e| e.to_string())?;
        let key = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;

        let mut name = X509NameBuilder::new().map_err(|e| e.to_string())?;
        name.append_entry_by_text("CN", cn)
            .map_err(|e| e.to_string())?;
        let name = name.build();

        let mut builder = X509::builder().map_err(|e| e.to_string())?;
        builder.set_version(2).map_err(|e| e.to_string())?;
        builder
            .set_subject_name(&name)
            .map_err(|e| e.to_string())?;
        // Self-signed: issuer == subject.
        builder
            .set_issuer_name(&name)
            .map_err(|e| e.to_string())?;
        builder
            .set_pubkey(&key)
            .map_err(|e| e.to_string())?;
        let not_before = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
        let not_after = Asn1Time::days_from_now(365).map_err(|e| e.to_string())?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| e.to_string())?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| e.to_string())?;
        builder
            .sign(&key, MessageDigest::sha256())
            .map_err(|e| e.to_string())?;
        let cert = builder.build();

        Ok(TlsIdentity { cert, key })
    }

    /// Server acceptor (TLS 1.2+ with sane defaults).
    pub fn acceptor(&self) -> Result<SslAcceptor, String> {
        let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(|e| e.to_string())?;
        b.set_certificate(&self.cert).map_err(|e| e.to_string())?;
        b.set_private_key(&self.key).map_err(|e| e.to_string())?;
        b.check_private_key().map_err(|e| e.to_string())?;
        Ok(b.build())
    }
}

/// Wraps a freshly accepted TCP stream into a TLS server stream.
pub async fn accept_tls(
    acceptor: &SslAcceptor,
    tcp: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>, String> {
    let ssl = openssl::ssl::Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    Pin::new(&mut stream)
        .accept()
        .await
        .map_err(|e| format!("tls accept: {e}"))?;
    Ok(stream)
}

/// Client-side TLS connector that accepts self-signed local certs (demo
/// topologies only).
pub fn client_connector() -> Result<SslConnector, String> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_verify(SslVerifyMode::NONE);
    Ok(b.build())
}

/// Connects a TLS client stream, skipping certificate verification.
pub async fn connect_tls(
    connector: &SslConnector,
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>, String> {
    let config = connector.configure().map_err(|e| e.to_string())?;
    let ssl = config
        .into_ssl(host)
        .map_err(|e| format!("tls client cfg: {e}"))?;
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|e| format!("tls connect: {e}"))?;
    Ok(stream)
}
