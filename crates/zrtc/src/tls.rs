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

/// Client-side identity for mTLS trunks (auth=tls_client_cert): the PEM
/// cert/key are presented during the handshake.
#[derive(Debug, Clone)]
pub struct TlsClientIdentity {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: Option<String>,
}

/// Client-side TLS connector that accepts self-signed local certs (demo
/// topologies only).
pub fn client_connector() -> Result<SslConnector, String> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_verify(SslVerifyMode::NONE);
    Ok(b.build())
}

/// Client connector presenting a client certificate (mTLS). Server cert
/// verification stays relaxed to match the demo topology the plain
/// connector serves; the optional CA bundle is loaded into the store.
pub fn client_connector_with_identity(id: &TlsClientIdentity) -> Result<SslConnector, String> {
    let cert_pem = std::fs::read(&id.cert_path)
        .map_err(|e| format!("tls client cert {}: {e}", id.cert_path))?;
    let key_pem = std::fs::read(&id.key_path)
        .map_err(|e| format!("tls client key {}: {e}", id.key_path))?;
    let cert = X509::from_pem(&cert_pem).map_err(|e| format!("parse client cert: {e}"))?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| format!("parse client key: {e}"))?;
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_certificate(&cert).map_err(|e| e.to_string())?;
    b.set_private_key(&key).map_err(|e| e.to_string())?;
    b.check_private_key().map_err(|e| e.to_string())?;
    if let Some(ca) = &id.ca_path {
        let ca_pem = std::fs::read(ca).map_err(|e| format!("tls ca {ca}: {e}"))?;
        for ca_cert in X509::stack_from_pem(&ca_pem)
            .map_err(|e| format!("parse ca bundle: {e}"))?
        {
            b.cert_store_mut()
                .add_cert(ca_cert)
                .map_err(|e| format!("load ca cert: {e}"))?;
        }
    }
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
