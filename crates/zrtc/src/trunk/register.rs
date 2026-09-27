//! The trunk REGISTER transaction: REGISTER → (401/407 → credentials →
//! re-REGISTER) → 200. The SIP-level retry lives here, not in sip-core.

use sip_core::message::{Method, SipMessage};

use crate::auth::{ChallengeOutcome, TrunkAuth};

use super::{recv_response, request, Endpoint};

/// Maximum challenge/retry rounds before giving up (protects against
/// wrong-password loops issuing fresh nonces forever).
const MAX_CHALLENGE_ROUNDS: u32 = 2;

/// Drives REGISTER on an established session to completion. Returns the
/// final response code (200 on success). On auth failure the raw challenge
/// has already been logged; the error aborts startup with a non-zero exit.
pub async fn run(
    sess: &mut crate::uac::Session,
    ep: &Endpoint,
    auth: &mut dyn TrunkAuth,
    expires: u32,
) -> Result<u16, String> {
    let uri = ep.aor.clone();
    let call_id = sip_core::ids::new_call_id("zrtc-trunk-reg");
    let from_tag = sip_core::ids::new_tag();
    let mut cseq: u32 = 0;

    // ---- initial REGISTER (auth may attach preemptive credentials) ------
    let mut extra: Vec<(String, String)> = Vec::new();
    auth.sign_request(Method::Register, &uri, &mut extra);
    cseq += 1;
    send(sess, ep, &uri, cseq, &call_id, &from_tag, expires, &extra).await?;
    let mut resp = recv_response(sess).await?;

    // ---- challenge rounds ------------------------------------------------
    let mut rounds = 0u32;
    while (resp.code == 401 || resp.code == 407) && rounds < MAX_CHALLENGE_ROUNDS {
        rounds += 1;
        let www = resp.headers.get("WWW-Authenticate").map(str::to_string);
        let proxy = resp
            .headers
            .get("Proxy-Authenticate")
            .map(str::to_string);
        // Log the raw challenge (never a credential).
        let raw = if resp.code == 407 {
            proxy.as_deref().or(www.as_deref())
        } else {
            www.as_deref().or(proxy.as_deref())
        };
        tracing::info!(
            "trunk REGISTER challenged with {}: {}",
            resp.code,
            raw.unwrap_or("(no challenge header)")
        );

        match auth.on_challenge(resp.code, www.as_deref(), proxy.as_deref()) {
            ChallengeOutcome::Retry => {
                // The retry header arrives by name; log the NAME only.
                let Some((name, value)) = auth.pending_header() else {
                    return Err("trunk auth returned Retry without a credential header".into());
                };
                tracing::info!("trunk retrying REGISTER with {name} header");
                cseq += 1;
                send(
                    sess,
                    ep,
                    &uri,
                    cseq,
                    &call_id,
                    &from_tag,
                    expires,
                    &[(name, value)],
                )
                .await?;
                resp = recv_response(sess).await?;
            }
            ChallengeOutcome::Fail(reason) => {
                tracing::error!("trunk REGISTER auth failed: {reason}");
                tracing::error!("trunk REGISTER challenge was: {}", raw.unwrap_or("(none)"));
                return Err(format!(
                    "trunk REGISTER failed after challenge ({}): {}",
                    resp.code, reason
                ));
            }
        }
    }

    if resp.code == 401 || resp.code == 407 {
        return Err(format!(
            "trunk REGISTER still challenged after {MAX_CHALLENGE_ROUNDS} retries (last code {})",
            resp.code
        ));
    }
    tracing::info!("trunk REGISTER final code {}", resp.code);
    if (200..300).contains(&resp.code) {
        Ok(resp.code)
    } else {
        Err(format!("trunk REGISTER rejected with {}", resp.code))
    }
}

async fn send(
    sess: &mut crate::uac::Session,
    ep: &Endpoint,
    uri: &str,
    cseq: u32,
    call_id: &str,
    from_tag: &str,
    expires: u32,
    extra: &[(String, String)],
) -> Result<(), String> {
    let mut all: Vec<(String, String)> = extra.to_vec();
    all.push(("Expires".to_string(), expires.to_string()));
    let reg = request(
        Method::Register,
        uri,
        ep,
        &sess.via(),
        call_id,
        cseq,
        from_tag,
        None,
        true,
        &all,
    )?;
    tracing::info!("trunk REGISTER {uri} (cseq {cseq})");
    sess.send_msg(&SipMessage::Request(reg)).await
}
