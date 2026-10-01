//! SIP registrar (RFC 3261 §10): processes REGISTER requests against an
//! in-memory binding database (Address-of-Record → Contact bindings), with
//! optional Digest authentication (RFC 3261 §22) reusing `sip_core::digest`.
//!
//! Extensions implemented on top of the base REGISTER:
//! - RFC 5626 Outbound: `+sip.instance` + `reg-id` bindings, flow detection
//!   via the top Via transport, `Flow-Timer` and `Supported: outbound` echo
//!   for reliable-transport registrations.
//! - RFC 5627 GRUU: a public GRUU (`sip:aor;gr=<instance>`) is synthesized
//!   for every contact that registers a `+sip.instance` and echoed in the
//!   200 OK alongside `Supported: gruu`.
//!
//! The registrar is transport-agnostic: [`Registrar::process`] takes a
//! parsed request plus the transport source and returns the response to
//! send, which keeps the protocol logic unit-testable.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sip_core::builder::respond_to;
use sip_core::digest::{Algorithm, Qop};
use sip_core::message::Method;
use sip_core::uri::TransportKind;
use sip_core::{Request, Response};

/// Errors surfaced by the registrar.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrarError {
    /// Malformed or unsupported request shape.
    #[error("bad request: {0}")]
    BadRequest(&'static str),
}

/// One contact binding under an AoR.
#[derive(Debug, Clone)]
pub struct Binding {
    /// Contact URI as registered (without display name).
    pub contact: String,
    /// Transport source the REGISTER arrived from (NAT-correct routing).
    pub source: String,
    /// Relative preference (RFC 3261 §10.2.1.2), default 1.0.
    pub q: f32,
    /// Absolute expiry instant.
    pub expires_at: Instant,
    /// Registration consistency bookkeeping (§10.2.4).
    pub call_id: String,
    pub cseq: u32,
    /// `+sip.instance` value (RFC 5626 §9.1) when registered with one.
    pub instance: Option<String>,
    /// `reg-id` (RFC 5626 §9.4); 0 = absent. Multiple reg-ids under one
    /// instance are distinct bindings (one per client flow).
    pub reg_id: u32,
    /// Public GRUU synthesized for this binding (RFC 5627 §4.3), present
    /// only when the contact registered a `+sip.instance`.
    pub pub_gruu: Option<String>,
    /// True when the registration arrived over a reliable-transport flow
    /// (TCP/TLS/WSS top Via), i.e. an Outbound-manageable connection.
    pub flow: bool,
}

impl Binding {
    /// Remaining registration lifetime in seconds (0 when expired).
    pub fn remaining(&self) -> u32 {
        self.expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
            .min(u32::MAX as u64) as u32
    }

    pub fn is_expired(&self) -> bool {
        self.remaining() == 0
    }
}

/// An address-of-record with its bindings.
#[derive(Debug, Default, Clone)]
pub struct Aor {
    pub bindings: Vec<Binding>,
}

impl Aor {
    /// Active (non-expired) bindings, best `q` first.
    pub fn active(&self) -> Vec<&Binding> {
        let mut v: Vec<&Binding> = self.bindings.iter().filter(|b| !b.is_expired()).collect();
        v.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}

/// Digest credential store: username → password.
#[derive(Debug, Clone, Default)]
pub struct AuthStore {
    pub users: HashMap<String, String>,
    pub realm: String,
    /// Nonce validity window.
    pub nonce_ttl: Duration,
    /// Active nonces → issued at.
    pub nonces: HashMap<String, Instant>,
}

impl AuthStore {
    pub fn new(realm: &str) -> Self {
        AuthStore {
            users: HashMap::new(),
            realm: realm.to_string(),
            nonce_ttl: Duration::from_secs(300),
            nonces: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, user: &str, pass: &str) {
        self.users.insert(user.to_string(), pass.to_string());
    }

    /// Builder-style user addition.
    pub fn with_user(mut self, user: &str, pass: &str) -> Self {
        self.add_user(user, pass);
        self
    }
}

/// Registrar configuration.
#[derive(Clone)]
pub struct RegistrarConfig {
    /// Domain served; the Request-URI host must contain it when set.
    pub domain: Option<String>,
    /// Minimum allowed expiry (RFC 3261 §10.2.8).
    pub min_expires: u32,
    /// Maximum allowed expiry (also the default when unspecified).
    pub max_expires: u32,
    /// Whether REGISTER requests must carry a valid Digest response.
    pub require_auth: bool,
    /// Keep-alive interval demanded from Outbound clients (RFC 5626 §4.2):
    /// echoed as `Flow-Timer` when a REGISTER negotiates Outbound over a
    /// reliable transport. MUST be shorter than any flow idle timeout on
    /// the path.
    pub flow_timer_secs: u64,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        RegistrarConfig {
            domain: None,
            min_expires: 60,
            max_expires: 3600,
            require_auth: false,
            flow_timer_secs: 120,
        }
    }
}

/// An in-memory SIP registrar.
pub struct Registrar {
    pub aors: HashMap<String, Aor>,
    pub auth: Option<AuthStore>,
    pub config: RegistrarConfig,
}

impl Registrar {
    pub fn new(config: RegistrarConfig) -> Self {
        Registrar {
            aors: HashMap::new(),
            auth: None,
            config,
        }
    }

    pub fn with_auth(mut self, auth: AuthStore) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Active bindings for an AoR (best q first).
    pub fn bindings(&self, aor: &str) -> Vec<&Binding> {
        self.aors.get(aor).map(|a| a.active()).unwrap_or_default()
    }

    /// Process an incoming REGISTER and return the response to send.
    pub fn process(&mut self, req: &Request, source: &str) -> Result<Response, RegistrarError> {
        if req.method != Method::Register {
            return Err(RegistrarError::BadRequest("not a REGISTER"));
        }

        let to = req
            .headers
            .to()
            .ok_or(RegistrarError::BadRequest("missing To header"))?;
        // NameAddr's Display includes angle brackets; the AoR is the bare
        // URI (RFC 3261 §10.3.4).
        let aor = strip_params(&to.addr.addr.to_string());

        // Domain check (RFC 3261 §10.3.4 step 1).
        if let Some(domain) = &self.config.domain {
            if !req.uri.host.to_string().contains(domain) {
                return Ok(respond_to(req, 404, "Not Found", Vec::new(), None));
            }
        }

        // Authentication.
        if self.config.require_auth {
            let auth = self
                .auth
                .as_mut()
                .ok_or(RegistrarError::BadRequest("auth required but no store"))?;
            match req.headers.authorization() {
                Some(auth_resp) => {
                    let pass = auth
                        .users
                        .get(&auth_resp.username.clone().unwrap_or_default());
                    let Some(pass) = pass else {
                        return Ok(respond_to(req, 403, "Forbidden", Vec::new(), None));
                    };
                    let pass = pass.clone();
                    let nonce_fresh = auth
                        .nonces
                        .get(&auth_resp.nonce.clone().unwrap_or_default())
                        .map(|t| t.elapsed() < auth.nonce_ttl)
                        .unwrap_or(false);
                    if !nonce_fresh {
                        // Stale/unknown nonce: challenge with a fresh nonce.
                        let nonce = issue_nonce(auth);
                        let mut resp = respond_to(req, 401, "Unauthorized", Vec::new(), None);
                        add_challenge(&mut resp, &auth.realm, &nonce);
                        return Ok(resp);
                    }
                    // Recompute the expected digest over this exact request,
                    // mirroring the qop mode the client chose (RFC 3261 §22.4).
                    let qop = match auth_resp.qop.as_deref() {
                        Some("auth-int") => Qop::AuthInt,
                        Some("auth") => Qop::Auth,
                        _ => Qop::None,
                    };
                    let expected = sip_core::digest::digest_response(
                        Algorithm::parse(Some(&auth_resp.algorithm.clone().unwrap_or_default())),
                        &auth_resp.username.clone().unwrap_or_default(),
                        &pass,
                        &auth_resp
                            .realm
                            .clone()
                            .unwrap_or_else(|| auth.realm.clone()),
                        "REGISTER",
                        &auth_resp.uri.clone().unwrap_or_default(),
                        &auth_resp.nonce.clone().unwrap_or_default(),
                        qop,
                        auth_resp.nc.as_deref().unwrap_or(""),
                        auth_resp.cnonce.as_deref().unwrap_or(""),
                        None,
                    );
                    if expected != auth_resp.response.clone().unwrap_or_default() {
                        let mut resp = respond_to(req, 401, "Unauthorized", Vec::new(), None);
                        add_challenge(
                            &mut resp,
                            &auth.realm,
                            &auth_resp.nonce.clone().unwrap_or_default(),
                        );
                        return Ok(resp);
                    }
                    // Nonces are single-use (RFC 3261 §22.4 recommends).
                    auth.nonces
                        .remove(&auth_resp.nonce.clone().unwrap_or_default());
                }
                None => {
                    let nonce = issue_nonce(auth);
                    let mut resp = respond_to(req, 401, "Unauthorized", Vec::new(), None);
                    add_challenge(&mut resp, &auth.realm, &nonce);
                    return Ok(resp);
                }
            }
        }

        // Wildcard contact "*" (§10.3.6): remove all bindings; only valid
        // together with Expires: 0.
        let contacts = req.headers.contacts();
        let header_expires = req.headers.expires().map(|e| e as u32);
        if contacts.star {
            if header_expires == Some(0) {
                self.aors.remove(&aor);
                return Ok(respond_to(req, 200, "OK", Vec::new(), None));
            }
            return Ok(respond_to(req, 400, "Bad Request", Vec::new(), None));
        }

        let call_id = req.headers.call_id().unwrap_or("").to_string();
        let cseq = req.headers.cseq().map(|c| c.seq).unwrap_or(0);
        let now = Instant::now();
        let default_expires = self.config.max_expires;

        // Flow detection (RFC 5626 §5.1): a registration over TCP/TLS/WSS
        // arrives on a connection the client can keep alive; UDP has no
        // flow to manage. Outbound is negotiated only when the client
        // advertises `Supported: outbound` AND the request used such a
        // transport.
        let flow = matches!(
            req.headers.first_via().as_ref().map(|v| &v.transport),
            Some(TransportKind::Tcp)
                | Some(TransportKind::Tls)
                | Some(TransportKind::Ws)
                | Some(TransportKind::Wss)
        );
        let outbound = flow && req.headers.supported().has("outbound");

        // Compute every contact's effective expiry FIRST: an expiry below
        // the configured minimum (RFC 3261 §10.2.8) is refused with
        // 423 (Interval Too Brief) carrying Min-Expires BEFORE any binding
        // is created or updated. Expiry 0 is de-registration, never 423.
        struct ContactReg {
            contact: String,
            expires: u32,
            q: f32,
            instance: Option<String>,
            reg_id: u32,
        }
        let mut computed: Vec<ContactReg> = Vec::with_capacity(contacts.addresses.len());
        for c in &contacts.addresses {
            let contact_str = c.addr.to_string();
            let param = |name: &str| {
                c.params
                    .iter()
                    .find(|p| p.name_eq(name))
                    .and_then(|p| p.value.clone())
            };
            let param_expires = param("expires").and_then(|v| v.parse::<u32>().ok());
            let expires = param_expires
                .or(header_expires)
                .unwrap_or(default_expires)
                .min(self.config.max_expires);
            let q = param("q")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(1.0);
            let instance = param("+sip.instance").filter(|v| !v.is_empty());
            // reg-id (RFC 5626 §9.4): must be a positive 32-bit number when
            // present. reg-id without +sip.instance is meaningless but not
            // an error; reg-id = 0 is a protocol violation (400).
            let reg_id = match param("reg-id") {
                Some(v) => match v.parse::<u32>() {
                    Ok(0) | Err(_) => {
                        return Ok(respond_to(req, 400, "Bad Request", Vec::new(), None));
                    }
                    Ok(id) => id,
                },
                None => 0,
            };
            if expires != 0 && expires < self.config.min_expires {
                let mut resp = respond_to(req, 423, "Interval Too Brief", Vec::new(), None);
                resp.headers
                    .add("Min-Expires", self.config.min_expires.to_string());
                return Ok(resp);
            }
            computed.push(ContactReg {
                contact: contact_str,
                expires,
                q,
                instance,
                reg_id,
            });
        }

        let existed = self.aors.contains_key(&aor);
        let entry = self.aors.entry(aor.clone()).or_default();
        let mut updates: Vec<(String, u32, u32)> = Vec::new();
        // AoR lookup tap (after lookup, before response)
        observ::session::emit_for(
            &call_id,
            observ::EventKind::RegistrarLookup {
                aor: aor.clone(),
                found: existed,
                bindings: contacts.addresses.len(),
            },
        );

        for c in &computed {
            // Pub-GRUU synthesis (RFC 5627 §4.3): registrar policy keeps it
            // simple — the AoR plus `;gr=<instance>`. Stable across
            // refreshes because the instance is stable.
            let pub_gruu = c.instance.as_ref().map(|inst| format!("{};gr={inst}", aor));
            updates.push((c.contact.clone(), c.expires, c.reg_id));
            if let Some(existing) = entry
                .bindings
                .iter_mut()
                .find(|b| b.contact == c.contact && b.call_id == call_id && b.reg_id == c.reg_id)
            {
                if c.expires == 0 {
                    continue; // removal handled below
                }
                if cseq >= existing.cseq {
                    existing.cseq = cseq;
                    existing.source = source.to_string();
                    existing.q = c.q;
                    existing.expires_at = now + Duration::from_secs(c.expires as u64);
                    existing.instance = c.instance.clone();
                    existing.pub_gruu = pub_gruu.clone();
                    existing.flow = flow;
                }
            } else if c.expires > 0 {
                entry.bindings.push(Binding {
                    contact: c.contact.clone(),
                    source: source.to_string(),
                    q: c.q,
                    expires_at: now + Duration::from_secs(c.expires as u64),
                    call_id: call_id.clone(),
                    cseq,
                    instance: c.instance.clone(),
                    reg_id: c.reg_id,
                    pub_gruu: pub_gruu.clone(),
                    flow,
                });
            }
        }

        // Apply removals / prune expired. A de-registration (Expires: 0)
        // only removes the binding it names: same contact, same Call-ID,
        // same reg-id (RFC 5626 §4.2 — other flows of the same instance
        // stay registered).
        for (contact, expires, reg_id) in &updates {
            if *expires == 0 {
                if let Some(e) = self.aors.get_mut(&aor) {
                    e.bindings.retain(|b| {
                        !(b.contact == *contact && b.call_id == call_id && b.reg_id == *reg_id)
                    });
                }
            }
        }
        if let Some(e) = self.aors.get_mut(&aor) {
            e.bindings.retain(|b| !b.is_expired());
        }

        // 200 OK echoing every current binding with its remaining expiry
        // (RFC 3261 §10.2.8), plus the Outbound/GRUU extension headers.
        let mut resp = respond_to(req, 200, "OK", Vec::new(), None);
        let any_instance = computed.iter().any(|c| c.instance.is_some());
        if let Some(e) = self.aors.get(&aor) {
            for b in e.active() {
                let mut v = format!("<{}>;expires={}", b.contact, b.remaining());
                if b.q != 1.0 {
                    v.push_str(&format!(";q={}", b.q));
                }
                if let Some(inst) = &b.instance {
                    // Quoted per RFC 3261 generic-param (URN is not a token).
                    v.push_str(&format!(";+sip.instance=\"{inst}\""));
                }
                if b.reg_id > 0 {
                    v.push_str(&format!(";reg-id={}", b.reg_id));
                }
                if let Some(gruu) = &b.pub_gruu {
                    // The GRUU URI contains `;`, so it must be quoted.
                    v.push_str(&format!(";pub-gruu=\"{gruu}\""));
                }
                resp.headers.add("Contact", v);
            }
        }
        // RFC 5626 §4.2: Flow-Timer only for negotiated Outbound over a
        // flow; the client must keep the connection alive within this
        // budget. RFC 5627 §4.2: Supported: gruu when the REGISTER
        // announced GRUU support or carried instance contacts.
        if outbound {
            resp.headers
                .add("Flow-Timer", self.config.flow_timer_secs.to_string());
            let mut tags = vec!["outbound"];
            if req.headers.supported().has("gruu") || any_instance {
                tags.push("gruu");
            }
            resp.headers.add("Supported", tags.join(", "));
            if req.headers.require().has("outbound") {
                resp.headers.add("Require", "outbound");
            }
        }
        Ok(resp)
    }

    /// Periodic sweep of expired bindings (call from a timer task).
    pub fn sweep_expired(&mut self) {
        for aor in self.aors.values_mut() {
            aor.bindings.retain(|b| !b.is_expired());
        }
    }
}

fn add_challenge(resp: &mut Response, realm: &str, nonce: &str) {
    resp.headers.add(
        "WWW-Authenticate",
        format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\""),
    );
}

/// Issues a fresh nonce, first evicting expired entries so the table cannot
/// grow without bound under challenge floods (audit 2026-09 P2: the table
/// previously only ever shrank on successful auth).
fn issue_nonce(auth: &mut AuthStore) -> String {
    auth.nonces
        .retain(|_, issued| issued.elapsed() < auth.nonce_ttl);
    let nonce = new_nonce();
    auth.nonces.insert(nonce.clone(), Instant::now());
    nonce
}

fn new_nonce() -> String {
    use rand::RngCore;
    let mut b = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn strip_params(uri: &str) -> String {
    let bare = uri.trim().trim_start_matches('<').trim_end_matches('>');
    bare.split(['?', ';']).next().unwrap_or(bare).to_string()
}
