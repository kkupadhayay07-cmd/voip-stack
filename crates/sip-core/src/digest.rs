//! HTTP Digest authentication (RFC 2617, RFC 7616 SHA-256 extension) —
//! challenge parsing lives in [`crate::headers::AuthChallenge`]; this module
//! computes responses.

use crate::error::{ParseError, Result};
use crate::headers::AuthChallenge;
use md5::{Digest as _, Md5};
use sha2::Sha256;

/// Hash algorithm for Digest (RFC 7616 adds SHA-256 family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// MD5 (RFC 2617).
    Md5,
    /// MD5-sess (session key re-hashed per nonce count).
    Md5Sess,
    /// SHA-256 (RFC 7616).
    Sha256,
    /// SHA-256-sess.
    Sha256Sess,
}

impl Algorithm {
    /// Parses an `algorithm=` token; defaults to MD5 when absent.
    pub fn parse(s: Option<&str>) -> Algorithm {
        match s.unwrap_or("MD5").to_ascii_uppercase().as_str() {
            "MD5-SESS" => Algorithm::Md5Sess,
            "SHA-256" => Algorithm::Sha256,
            "SHA-256-SESS" => Algorithm::Sha256Sess,
            _ => Algorithm::Md5,
        }
    }

    /// Token used in the Authorization header.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Md5 => "MD5",
            Algorithm::Md5Sess => "MD5-sess",
            Algorithm::Sha256 => "SHA-256",
            Algorithm::Sha256Sess => "SHA-256-Sess",
        }
    }

    fn hash_hex(self, parts: &[&str]) -> String {
        let joined = parts.join(":");
        match self {
            Algorithm::Md5 | Algorithm::Md5Sess => {
                let h = Md5::digest(joined.as_bytes());
                hex::encode(h)
            }
            Algorithm::Sha256 | Algorithm::Sha256Sess => {
                let mut h = Sha256::new();
                sha2::Digest::update(&mut h, joined.as_bytes());
                hex::encode(sha2::Digest::finalize(h))
            }
        }
    }
}

/// Quality-of-protection choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qop {
    /// Legacy mode without qop (RFC 2069 compatibility).
    None,
    /// `qop=auth` — authentication only.
    Auth,
    /// `qop=auth-int` — authentication + integrity (entity-body hash).
    AuthInt,
}

impl Qop {
    /// Chooses the qop from the challenge's option list (auth preferred over
    /// nothing; auth-int accepted when offered and requested).
    pub fn negotiate(offered: &[String], want_auth_int: bool) -> Qop {
        if want_auth_int && offered.iter().any(|q| q.eq_ignore_ascii_case("auth-int")) {
            return Qop::AuthInt;
        }
        if offered.iter().any(|q| q.eq_ignore_ascii_case("auth")) {
            return Qop::Auth;
        }
        if offered.is_empty() {
            Qop::None
        } else {
            Qop::Auth
        }
    }

    fn as_str(self) -> Option<&'static str> {
        match self {
            Qop::None => None,
            Qop::Auth => Some("auth"),
            Qop::AuthInt => Some("auth-int"),
        }
    }
}

/// Computes the hex `response` digest for a request.
///
/// * `nc` — nonce count text, e.g. `00000001` (ignored for `Qop::None`).
/// * `cnonce` — client nonce (ignored for `Qop::None`).
/// * `entity_body_hash` — for `auth-int`, the hex hash of the body; pass
///   `None` to hash the empty string.
#[allow(clippy::too_many_arguments)]
pub fn digest_response(
    algorithm: Algorithm,
    username: &str,
    password: &str,
    realm: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Qop,
    nc: &str,
    cnonce: &str,
    entity_body_hash: Option<&str>,
) -> String {
    let mut ha1 = algorithm.hash_hex(&[username, realm, password]);
    if matches!(algorithm, Algorithm::Md5Sess | Algorithm::Sha256Sess) {
        ha1 = algorithm.hash_hex(&[&ha1, nonce, cnonce]);
    }
    let ha2 = match qop {
        Qop::AuthInt => {
            let empty;
            let body = match entity_body_hash {
                Some(b) => b,
                None => {
                    empty = algorithm.hash_hex(&[""]);
                    &empty
                }
            };
            algorithm.hash_hex(&[method, uri, body])
        }
        _ => algorithm.hash_hex(&[method, uri]),
    };
    match qop.as_str() {
        Some(q) => algorithm.hash_hex(&[&ha1, nonce, nc, cnonce, q, &ha2]),
        None => algorithm.hash_hex(&[&ha1, nonce, &ha2]),
    }
}

/// Convenience: builds a complete `Authorization` value for a challenge.
#[allow(clippy::too_many_arguments)]
pub fn respond_to_challenge(
    challenge: &AuthChallenge,
    method: &str,
    uri: &str,
    username: &str,
    password: &str,
    nc: u32,
    cnonce: &str,
    want_auth_int: bool,
) -> Result<crate::headers::AuthResponse> {
    let realm = challenge
        .realm
        .clone()
        .ok_or_else(|| ParseError::malformed("challenge without realm"))?;
    let nonce = challenge
        .nonce
        .clone()
        .ok_or_else(|| ParseError::malformed("challenge without nonce"))?;
    let algorithm = Algorithm::parse(challenge.algorithm.as_deref());
    let qop = Qop::negotiate(&challenge.qop, want_auth_int);
    let nc_text = format!("{nc:08x}");
    let response = digest_response(
        algorithm, username, password, &realm, method, uri, &nonce, qop, &nc_text, cnonce, None,
    );
    Ok(crate::headers::AuthResponse {
        username: Some(username.to_string()),
        realm: Some(realm),
        nonce: Some(nonce),
        uri: Some(uri.to_string()),
        response: Some(response),
        algorithm: Some(algorithm.as_str().to_string()),
        cnonce: if qop == Qop::None {
            None
        } else {
            Some(cnonce.to_string())
        },
        nc: if qop == Qop::None {
            None
        } else {
            Some(nc_text)
        },
        qop: qop.as_str().map(str::to_string),
        opaque: challenge.opaque.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2617 §3.5 example: GET /dir/index.html with the documented
    /// credentials and qop=auth yields the documented response digest.
    #[test]
    fn rfc2617_reference_vector() {
        let resp = digest_response(
            Algorithm::Md5,
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "GET",
            "/dir/index.html",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            Qop::Auth,
            "00000001",
            "0a4f113b",
            None,
        );
        assert_eq!(resp, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn qop_none_legacy_mode() {
        // RFC 2069 form: HA1:nonce:HA2 (no nc/cnonce/qop).
        let a = digest_response(
            Algorithm::Md5,
            "u",
            "p",
            "r",
            "REGISTER",
            "sip:x@y",
            "nonce1",
            Qop::None,
            "",
            "",
            None,
        );
        let ha1 = {
            let h = Md5::digest(b"u:r:p");
            hex::encode(h)
        };
        let ha2 = {
            let h = Md5::digest(b"REGISTER:sip:x@y");
            hex::encode(h)
        };
        let expect = {
            let joined = format!("{ha1}:nonce1:{ha2}");
            let h = Md5::digest(joined.as_bytes());
            hex::encode(h)
        };
        assert_eq!(a, expect);
    }

    #[test]
    fn sha256_algorithm_differs_from_md5() {
        let md5 = digest_response(
            Algorithm::Md5,
            "u",
            "p",
            "r",
            "GET",
            "/",
            "n",
            Qop::Auth,
            "00000001",
            "c",
            None,
        );
        let sha = digest_response(
            Algorithm::Sha256,
            "u",
            "p",
            "r",
            "GET",
            "/",
            "n",
            Qop::Auth,
            "00000001",
            "c",
            None,
        );
        assert_ne!(md5, sha);
        assert_eq!(sha.len(), 64);
    }

    #[test]
    fn qop_negotiation() {
        assert_eq!(
            Qop::negotiate(&["auth".to_string(), "auth-int".to_string()], false),
            Qop::Auth
        );
        assert_eq!(
            Qop::negotiate(&["auth-int".to_string()], true),
            Qop::AuthInt
        );
        assert_eq!(Qop::negotiate(&[], false), Qop::None);
        assert_eq!(Qop::negotiate(&["auth".to_string()], true), Qop::Auth);
    }

    #[test]
    fn respond_to_challenge_end_to_end() {
        let challenge = AuthChallenge::parse(
            "Digest realm=\"atlanta.com\", nonce=\"n1\", qop=\"auth\", opaque=\"o\"",
        )
        .unwrap();
        let resp = respond_to_challenge(
            &challenge,
            "REGISTER",
            "sip:atlanta.com",
            "bob",
            "pw",
            1,
            "cn",
            false,
        )
        .unwrap();
        assert_eq!(resp.username.as_deref(), Some("bob"));
        assert_eq!(resp.nc.as_deref(), Some("00000001"));
        assert_eq!(resp.response.unwrap().len(), 32);
        assert_eq!(resp.opaque.as_deref(), Some("o"));
        let missing = AuthChallenge::parse("Digest realm=\"r\"").unwrap();
        assert!(respond_to_challenge(&missing, "GET", "/", "u", "p", 1, "c", false).is_err());
    }
}
