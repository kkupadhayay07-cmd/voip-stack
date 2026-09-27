//! Pluggable trunk authentication: IP peering, Digest (RFC 3261 §22.4 /
//! RFC 7616), static Bearer tokens, and TLS client certificates. The mode
//! is picked from `[trunk] auth` in the config; `build` is the factory.

mod bearer_auth;
mod digest_auth;
mod ip_auth;
mod tls_cert_auth;

use sip_core::message::Method;

use crate::config::Trunk;

pub use bearer_auth::BearerAuth;
pub use digest_auth::DigestAuth;
pub use ip_auth::IpAuth;
pub use tls_cert_auth::TlsCertAuth;

/// What the authenticator decided after seeing a 401/407.
pub enum ChallengeOutcome {
    /// Credentials were produced: `pending_header` now yields the header
    /// to attach to the re-sent request.
    Retry,
    /// Authentication cannot proceed; carries the reason. The raw challenge
    /// is logged by the caller.
    Fail(String),
}

/// Per-tick context handed to [`TrunkAuth::on_keepalive`].
pub struct KeepaliveCtx {
    /// Target URI for the keepalive request (the trunk address).
    pub uri: String,
    /// Credential headers the mode wants attached to the keepalive request.
    pub headers: Vec<(String, String)>,
}

/// One vendor trunk authentication mode.
pub trait TrunkAuth: Send {
    /// Mode name for the `trunk configured: ... auth=<mode>` log line.
    fn mode(&self) -> &'static str;

    /// Attach pre-challenge credentials to an outgoing request. Also
    /// records the (method, uri) context used by a later `on_challenge`.
    fn sign_request(&self, method: Method, uri: &str, headers: &mut Vec<(String, String)>);

    /// Handle a 401/407. `www` / `proxy` are the raw `WWW-Authenticate` /
    /// `Proxy-Authenticate` header values (None when absent).
    fn on_challenge(
        &mut self,
        status: u16,
        www: Option<&str>,
        proxy: Option<&str>,
    ) -> ChallengeOutcome;

    /// After [`ChallengeOutcome::Retry`]: the credential header (name, value)
    /// for the re-sent request. Log the name only — never the value.
    fn pending_header(&self) -> Option<(String, String)>;

    /// Periodic keepalive hook; push onto `ctx.headers` to attach
    /// credentials to the keepalive request.
    fn on_keepalive(&mut self, ctx: &mut KeepaliveCtx);
}

/// Factory: builds the authenticator named by `cfg.auth` (default `ip`).
pub fn build(cfg: &Trunk) -> Result<Box<dyn TrunkAuth>, String> {
    let mode = cfg.auth.as_deref().unwrap_or("ip");
    match mode {
        "ip" => Ok(Box::new(IpAuth)),
        "digest" => {
            let user = cfg
                .auth_user
                .clone()
                .ok_or("trunk auth=digest requires auth_user (or ZRTC_TRUNK_USER)")?;
            let pass = cfg
                .auth_pass
                .clone()
                .ok_or("trunk auth=digest requires auth_pass (or ZRTC_TRUNK_PASS)")?;
            Ok(Box::new(DigestAuth::new(user, pass, cfg.auth_realm.clone())))
        }
        "bearer" => {
            let token = cfg
                .auth_token
                .clone()
                .ok_or("trunk auth=bearer requires auth_token (or ZRTC_TRUNK_TOKEN)")?;
            Ok(Box::new(BearerAuth::new(token, cfg.auth_header.clone())))
        }
        "tls_client_cert" => Ok(Box::new(TlsCertAuth::new(cfg)?)),
        other => Err(format!(
            "unknown trunk auth mode '{other}' (ip | digest | bearer | tls_client_cert)"
        )),
    }
}
