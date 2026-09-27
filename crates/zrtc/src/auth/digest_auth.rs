//! Digest authentication (RFC 3261 §22.4, RFC 7616 algorithms): handles
//! 401 (WWW-Authenticate → Authorization) and 407 (Proxy-Authenticate →
//! Proxy-Authorization) challenges for both REGISTER-on-start and
//! INVITE-only trunks. All hashing lives in `sip_core::digest`.

use std::sync::Mutex;

use sip_core::digest::{digest_response, respond_to_challenge, Algorithm, Qop};
use sip_core::headers::{AuthChallenge, AuthResponse};
use sip_core::message::Method;

use super::{ChallengeOutcome, KeepaliveCtx, TrunkAuth};

/// Credentials cached from the last resolved challenge, reused for
/// preemptive signing of later requests (REGISTER refresh, INVITE, OPTIONS).
struct Creds {
    realm: String,
    nonce: String,
    algorithm: Algorithm,
    qop: Qop,
    cnonce: String,
    opaque: Option<String>,
    nc: u32,
}

#[derive(Default)]
struct Inner {
    /// (method, uri) of the request currently in flight — recorded by
    /// `sign_request`, consumed by `on_challenge`.
    last_req: Option<(Method, String)>,
    creds: Option<Creds>,
    pending: Option<(String, String)>,
}

/// RFC 3261/7616 Digest authenticator.
pub struct DigestAuth {
    user: String,
    pass: String,
    /// Realm fallback for challenges that omit `realm=`.
    realm_override: Option<String>,
    inner: Mutex<Inner>,
}

fn new_cnonce() -> String {
    format!("{:016x}", rand::random::<u64>())
}

fn qop_str(q: &Qop) -> Option<&'static str> {
    match q {
        Qop::None => None,
        Qop::Auth => Some("auth"),
        Qop::AuthInt => Some("auth-int"),
    }
}

impl DigestAuth {
    pub fn new(user: String, pass: String, realm_override: Option<String>) -> Self {
        DigestAuth {
            user,
            pass,
            realm_override,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Renders a full Authorization/Proxy-Authorization value from cached
    /// credentials for (method, uri).
    fn render(creds: &Creds, user: &str, pass: &str, method: &str, uri: &str) -> AuthResponse {
        let nc_text = format!("{:08x}", creds.nc);
        let response = digest_response(
            creds.algorithm,
            user,
            pass,
            &creds.realm,
            method,
            uri,
            &creds.nonce,
            creds.qop,
            &nc_text,
            &creds.cnonce,
            None,
        );
        AuthResponse {
            username: Some(user.to_string()),
            realm: Some(creds.realm.clone()),
            nonce: Some(creds.nonce.clone()),
            uri: Some(uri.to_string()),
            response: Some(response),
            algorithm: Some(creds.algorithm.as_str().to_string()),
            cnonce: Some(creds.cnonce.clone()),
            nc: Some(nc_text),
            qop: qop_str(&creds.qop).map(str::to_string),
            opaque: creds.opaque.clone(),
        }
    }
}

impl TrunkAuth for DigestAuth {
    fn mode(&self) -> &'static str {
        "digest"
    }

    fn sign_request(&self, method: Method, uri: &str, headers: &mut Vec<(String, String)>) {
        let method_str = method.as_str().to_string();
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        g.last_req = Some((method, uri.to_string()));
        if let Some(c) = &mut g.creds {
            // Preemptive signing with the cached nonce (nc increments).
            c.nc = c.nc.wrapping_add(1);
            let value = Self::render(c, &self.user, &self.pass, &method_str, uri);
            headers.push(("Authorization".to_string(), value.to_string()));
        }
    }

    fn on_challenge(
        &mut self,
        status: u16,
        www: Option<&str>,
        proxy: Option<&str>,
    ) -> ChallengeOutcome {
        let (method, uri) = match self.inner.lock().ok().and_then(|g| g.last_req.clone()) {
            Some(x) => x,
            None => {
                return ChallengeOutcome::Fail(
                    "no request context: sign_request was not called before the exchange"
                        .to_string(),
                )
            }
        };

        // 401 → WWW-Authenticate, 407 → Proxy-Authenticate (fallback to the
        // other when the vendor used the "wrong" one).
        let raw = if status == 407 {
            proxy.or(www)
        } else {
            www.or(proxy)
        };
        let Some(raw) = raw else {
            return ChallengeOutcome::Fail(format!(
                "{status} without a WWW-Authenticate/Proxy-Authenticate header"
            ));
        };
        if !raw.trim_start().to_ascii_lowercase().starts_with("digest") {
            return ChallengeOutcome::Fail(format!(
                "unsupported challenge scheme (only Digest; got: {status} challenge)"
            ));
        }
        let mut ch = match AuthChallenge::parse(raw) {
            Ok(c) => c,
            Err(e) => return ChallengeOutcome::Fail(format!("unparseable challenge: {e}")),
        };
        if ch.realm.is_none() {
            ch.realm = self.realm_override.clone();
        }
        let cnonce = new_cnonce();
        let resp = match respond_to_challenge(
            &ch,
            method.as_str(),
            &uri,
            &self.user,
            &self.pass,
            1,
            &cnonce,
            false,
        ) {
            Ok(r) => r,
            Err(e) => return ChallengeOutcome::Fail(format!("cannot build credentials: {e}")),
        };

        let header_name = if status == 407 {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };
        if let Ok(mut g) = self.inner.lock() {
            g.creds = Some(Creds {
                realm: ch.realm.clone().unwrap_or_default(),
                nonce: ch.nonce.clone().unwrap_or_default(),
                algorithm: Algorithm::parse(ch.algorithm.as_deref()),
                qop: Qop::negotiate(&ch.qop, false),
                cnonce,
                opaque: ch.opaque.clone(),
                nc: 1,
            });
            g.pending = Some((header_name.to_string(), resp.to_string()));
        }
        ChallengeOutcome::Retry
    }

    fn pending_header(&self) -> Option<(String, String)> {
        self.inner.lock().ok().and_then(|g| g.pending.clone())
    }

    fn on_keepalive(&mut self, ctx: &mut KeepaliveCtx) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(c) = &mut g.creds {
            c.nc = c.nc.wrapping_add(1);
            let value = Self::render(c, &self.user, &self.pass, "OPTIONS", &ctx.uri);
            ctx.headers.push(("Authorization".to_string(), value.to_string()));
        }
    }
}
