//! TLS client-certificate authentication: the credential is presented at
//! the TLS handshake layer (mTLS), so there is nothing to attach to SIP
//! messages. This module validates the configured paths at startup and
//! ensures the transport is TLS; the certificate itself is loaded by the
//! client connector in `crate::tls` and presented by the trunk session.

use sip_core::message::Method;

use crate::config::Trunk;

use super::{ChallengeOutcome, KeepaliveCtx, TrunkAuth};

/// Certificate-identity authenticator (validation only; presentation
/// happens in the TLS transport layer).
pub struct TlsCertAuth;

impl TlsCertAuth {
    /// Validates that the transport is TLS and the configured PEM files
    /// exist and are readable. Fails fast (non-zero exit) on misconfig.
    pub fn new(cfg: &Trunk) -> Result<Self, String> {
        if cfg.transport != "tls" {
            return Err(format!(
                "trunk auth=tls_client_cert requires transport=\"tls\" (got {:?})",
                cfg.transport
            ));
        }
        let cert = cfg
            .tls_cert_path
            .as_deref()
            .ok_or("trunk auth=tls_client_cert requires tls_cert_path")?;
        let key = cfg
            .tls_key_path
            .as_deref()
            .ok_or("trunk auth=tls_client_cert requires tls_key_path")?;
        for (label, path) in [("tls_cert_path", cert), ("tls_key_path", key)] {
            std::fs::read(path)
                .map_err(|e| format!("trunk {label} \"{path}\" is not readable: {e}"))?;
        }
        if let Some(ca) = cfg.tls_ca_path.as_deref() {
            std::fs::read(ca).map_err(|e| format!("trunk tls_ca_path \"{ca}\" is not readable: {e}"))?;
        }
        Ok(TlsCertAuth)
    }
}

impl TrunkAuth for TlsCertAuth {
    fn mode(&self) -> &'static str {
        "tls_client_cert"
    }

    fn sign_request(&self, _method: Method, _uri: &str, _headers: &mut Vec<(String, String)>) {
        // The credential is the TLS client certificate; no SIP header.
    }

    fn on_challenge(
        &mut self,
        status: u16,
        _www: Option<&str>,
        _proxy: Option<&str>,
    ) -> ChallengeOutcome {
        // Certificate identity is negotiated at handshake time; a SIP
        // challenge means the vendor did not accept our TLS identity.
        ChallengeOutcome::Fail(format!(
            "tls_client_cert has no SIP credentials; vendor replied {status} (check the client certificate and CA trust)"
        ))
    }

    fn pending_header(&self) -> Option<(String, String)> {
        None
    }

    fn on_keepalive(&mut self, _ctx: &mut KeepaliveCtx) {
        // Plain OPTIONS over the mTLS connection.
    }
}
