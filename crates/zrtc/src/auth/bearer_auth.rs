//! Static Bearer token authentication: every outgoing request carries the
//! configured header (default `Authorization`). The value is
//! `Bearer <auth_token>` unless `auth_header` overrides the raw value.

use sip_core::message::Method;

use super::{ChallengeOutcome, KeepaliveCtx, TrunkAuth};

/// Constant-token authenticator.
pub struct BearerAuth {
    token: String,
    /// Raw value override; when set it is sent verbatim instead of
    /// `Bearer <token>`.
    raw_value: Option<String>,
}

impl BearerAuth {
    pub fn new(token: String, raw_value: Option<String>) -> Self {
        BearerAuth { token, raw_value }
    }

    fn value(&self) -> String {
        match &self.raw_value {
            Some(v) => v.clone(),
            None => format!("Bearer {}", self.token),
        }
    }
}

impl TrunkAuth for BearerAuth {
    fn mode(&self) -> &'static str {
        "bearer"
    }

    fn sign_request(&self, _method: Method, _uri: &str, headers: &mut Vec<(String, String)>) {
        headers.push(("Authorization".to_string(), self.value()));
    }

    fn on_challenge(
        &mut self,
        status: u16,
        _www: Option<&str>,
        _proxy: Option<&str>,
    ) -> ChallengeOutcome {
        // A static token cannot be re-derived from a challenge: a 401/407
        // means the token itself was rejected.
        ChallengeOutcome::Fail(format!(
            "bearer token rejected with {status} (rotate the token; no SIP-level retry is possible)"
        ))
    }

    fn pending_header(&self) -> Option<(String, String)> {
        None
    }

    fn on_keepalive(&mut self, ctx: &mut KeepaliveCtx) {
        ctx.headers
            .push(("Authorization".to_string(), self.value()));
    }
}
