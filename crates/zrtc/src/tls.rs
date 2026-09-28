//! TLS plumbing for the daemon: a self-signed certificate generated at
//! startup (the same OpenSSL backend the `dtls` crate uses) plus server
//! acceptor and (verification-relaxed) client connector helpers.

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509};
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
        builder.set_subject_name(&name).map_err(|e| e.to_string())?;
        // Self-signed: issuer == subject.
        builder.set_issuer_name(&name).map_err(|e| e.to_string())?;
        builder.set_pubkey(&key).map_err(|e| e.to_string())?;
        let not_before = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
        let not_after = Asn1Time::days_from_now(365).map_err(|e| e.to_string())?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| e.to_string())?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| e.to_string())?;
        // Mark the cert as its own (mini-)CA: OpenSSL 3 refuses to treat a
        // bare self-signed end-entity cert as a trust anchor, so pinning
        // this cert via `ca_path` would never verify without these
        // extensions.
        let bc = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(|e| e.to_string())?;
        builder.append_extension(bc).map_err(|e| e.to_string())?;
        let skid = {
            let ctx = builder.x509v3_context(None, None);
            SubjectKeyIdentifier::new()
                .build(&ctx)
                .map_err(|e| e.to_string())?
        };
        builder.append_extension(skid).map_err(|e| e.to_string())?;
        let akid = {
            let ctx = builder.x509v3_context(None, None);
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&ctx)
                .map_err(|e| e.to_string())?
        };
        builder.append_extension(akid).map_err(|e| e.to_string())?;
        // Subject Alt Name matching the CN (IP or DNS): clients that verify
        // the server certificate also check the hostname they connected to,
        // and modern verifiers ignore CN entirely.
        let san = {
            let ctx = builder.x509v3_context(None, None);
            let mut san = SubjectAlternativeName::new();
            if cn.parse::<std::net::IpAddr>().is_ok() {
                san.ip(cn);
            } else {
                san.dns(cn);
            }
            san.build(&ctx).map_err(|e| e.to_string())?
        };
        builder.append_extension(san).map_err(|e| e.to_string())?;
        builder
            .sign(&key, MessageDigest::sha256())
            .map_err(|e| e.to_string())?;
        let cert = builder.build();

        Ok(TlsIdentity { cert, key })
    }

    /// Server acceptor (TLS 1.2+ with sane defaults).
    pub fn acceptor(&self) -> Result<SslAcceptor, String> {
        let mut b =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(|e| e.to_string())?;
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

/// Client connector presenting a client certificate (mTLS). When a CA
/// bundle is configured the server certificate is chain-VERIFIED against
/// it (previously the bundle was loaded into the store but verification
/// stayed off, silently ignoring the operator's trust anchor — audit
/// 2026-09 P2); demo topologies without a CA keep the relaxed mode.
pub fn client_connector_with_identity(id: &TlsClientIdentity) -> Result<SslConnector, String> {
    let cert_pem = std::fs::read(&id.cert_path)
        .map_err(|e| format!("tls client cert {}: {e}", id.cert_path))?;
    let key_pem =
        std::fs::read(&id.key_path).map_err(|e| format!("tls client key {}: {e}", id.key_path))?;
    let cert = X509::from_pem(&cert_pem).map_err(|e| format!("parse client cert: {e}"))?;
    let key = PKey::private_key_from_pem(&key_pem).map_err(|e| format!("parse client key: {e}"))?;
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_certificate(&cert).map_err(|e| e.to_string())?;
    b.set_private_key(&key).map_err(|e| e.to_string())?;
    b.check_private_key().map_err(|e| e.to_string())?;
    let mut have_ca = false;
    if let Some(ca) = &id.ca_path {
        let ca_pem = std::fs::read(ca).map_err(|e| format!("tls ca {ca}: {e}"))?;
        for ca_cert in X509::stack_from_pem(&ca_pem).map_err(|e| format!("parse ca bundle: {e}"))? {
            b.cert_store_mut()
                .add_cert(ca_cert)
                .map_err(|e| format!("load ca cert: {e}"))?;
            have_ca = true;
        }
    }
    if have_ca {
        b.set_verify(SslVerifyMode::PEER);
    } else {
        b.set_verify(SslVerifyMode::NONE);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a generated identity's PEMs to a temp dir; returns the cert,
    /// key, CA-bundle paths and the identity itself (for the server side).
    /// `cn` doubles as the file stem and the certificate name.
    fn write_identity(
        dir: &std::path::Path,
        name: &str,
        cn: &str,
    ) -> (String, String, String, TlsIdentity) {
        std::fs::create_dir_all(dir).unwrap();
        let id = TlsIdentity::generate(cn).unwrap();
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        let ca = dir.join(format!("{name}-ca.pem"));
        std::fs::write(&cert, id.cert.to_pem().unwrap()).unwrap();
        std::fs::write(&key, id.key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write(&ca, id.cert.to_pem().unwrap()).unwrap();
        (
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
            ca.to_string_lossy().into_owned(),
            id,
        )
    }

    /// Regression (audit 2026-09 P2): a configured CA bundle must actually
    /// verify the server certificate — a server presenting a cert outside
    /// the trust anchor must fail the handshake, one presenting the CA's
    /// own cert must succeed.
    #[tokio::test]
    async fn identity_connector_with_ca_verifies_server_cert() {
        let tmp = std::env::temp_dir().join(format!("zrtc-tls-test-{}", std::process::id()));
        // The server identity's name must match the host the client dials
        // (SAN check), so the "server-a" files carry CN 127.0.0.1.
        let (cert, key, ca, server_id) = write_identity(&tmp, "server-a", "127.0.0.1");
        let (_c2, _k2, ca_other, _id2) = write_identity(&tmp, "server-b", "other.example");

        // Server presents exactly the cert the CA bundle pins.
        let acceptor = server_id.acceptor().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let _ = accept_tls(&acceptor, tcp).await;
            }
        });

        // Verified against the matching CA: handshake succeeds.
        let good = client_connector_with_identity(&TlsClientIdentity {
            cert_path: cert.clone(),
            key_path: key.clone(),
            ca_path: Some(ca.clone()),
        })
        .unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connect_tls(&good, "127.0.0.1", tcp)
            .await
            .expect("server cert must verify against its own CA");

        // Verified against a DIFFERENT CA: handshake must fail.
        let bad = client_connector_with_identity(&TlsClientIdentity {
            cert_path: cert,
            key_path: key,
            ca_path: Some(ca_other),
        })
        .unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            connect_tls(&bad, "127.0.0.1", tcp).await.is_err(),
            "foreign CA must not verify the server cert"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
