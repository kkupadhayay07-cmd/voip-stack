//! The trunk REGISTER transaction: REGISTER → (401/407 → credentials →
//! re-REGISTER) → 200. The SIP-level retry lives here, not in sip-core.
//!
//! RFC 5626 Outbound support: REGISTERs advertise `Supported: outbound,
//! gruu`, carry `+sip.instance`/`reg-id` on the Contact (built by the
//! trunk request helper), and the final 2xx is mined for `Flow-Timer`
//! (flow keep-alive budget) and the granted expiry (refresh cadence).

use sip_core::message::{Method, SipMessage};

use crate::auth::{ChallengeOutcome, TrunkAuth};

use super::{recv_response, request, Endpoint};

/// Maximum challenge/retry rounds before giving up (protects against
/// wrong-password loops issuing fresh nonces forever).
const MAX_CHALLENGE_ROUNDS: u32 = 2;

/// State of one live registration on a trunk flow.
#[derive(Debug, Clone)]
pub struct Flow {
    /// Registration Call-ID. Refreshes REUSE it with an incrementing
    /// CSeq (RFC 3261 §10.2.4 freshness is per Call-ID, and the registrar
    /// upserts bindings keyed on contact + Call-ID + reg-id).
    pub call_id: String,
    /// From-tag of the registration dialog.
    pub from_tag: String,
    /// Last CSeq sent on this registration.
    pub cseq: u32,
    /// `Flow-Timer` from the 2xx (seconds): how often to keep the
    /// reliable-transport flow alive. None = server did not negotiate
    /// Outbound (UDP trunks, or an Outbound-less server).
    pub flow_timer: Option<u64>,
    /// Granted expiry in seconds (from the echoed Contact/Expires,
    /// falling back to what we asked for).
    pub expires: u32,
}

impl Flow {
    /// Registration refresh cadence: half the granted expiry (RFC 3261
    /// §10.2.4 recommends refreshing before expiry), clamped to a sane
    /// minimum so tiny test/expiry values cannot hot-loop.
    pub fn refresh_interval_secs(&self) -> u64 {
        (self.expires as u64 / 2).max(1)
    }
}

/// Drives REGISTER on an established session to completion. Returns the
/// live [`Flow`] (Call-ID/tag/CSeq state + keep-alive/refresh budgets).
/// On auth failure the raw challenge has already been logged; the error
/// aborts startup with a non-zero exit.
pub async fn run(
    sess: &mut crate::uac::Session,
    ep: &Endpoint,
    auth: &mut dyn TrunkAuth,
    expires: u32,
) -> Result<Flow, String> {
    let uri = ep.aor.clone();
    let call_id = sip_core::ids::new_call_id("zrtc-trunk-reg");
    let from_tag = sip_core::ids::new_tag();
    let mut flow = Flow {
        call_id,
        from_tag,
        cseq: 0,
        flow_timer: None,
        expires,
    };

    // ---- initial REGISTER (auth may attach preemptive credentials) ------
    let mut extra: Vec<(String, String)> = Vec::new();
    auth.sign_request(Method::Register, &uri, &mut extra);
    flow.cseq += 1;
    send(sess, ep, &uri, &flow, &extra).await?;
    let mut resp = recv_response(sess).await?;

    // ---- challenge rounds ------------------------------------------------
    let mut rounds = 0u32;
    while (resp.code == 401 || resp.code == 407) && rounds < MAX_CHALLENGE_ROUNDS {
        rounds += 1;
        let www = resp.headers.get("WWW-Authenticate").map(str::to_string);
        let proxy = resp.headers.get("Proxy-Authenticate").map(str::to_string);
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
                flow.cseq += 1;
                send(sess, ep, &uri, &flow, &[(name, value)]).await?;
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
        // Mine the 2xx for the flow budgets. A missing Flow-Timer simply
        // means the server did not negotiate Outbound (UDP peers do not).
        flow.flow_timer = resp
            .headers
            .get("Flow-Timer")
            .and_then(|v| v.trim().parse::<u64>().ok());
        flow.expires = response_expires(&resp, &ep.contact).unwrap_or(expires);
        tracing::info!(
            "trunk REGISTER granted expiry {}s, flow-timer {}",
            flow.expires,
            flow.flow_timer
                .map(|t| t.to_string())
                .unwrap_or_else(|| "off".into())
        );
        Ok(flow)
    } else {
        Err(format!("trunk REGISTER rejected with {}", resp.code))
    }
}

/// Re-REGISTER on an already-live flow: same Call-ID/From-tag, next CSeq,
/// full expiry. Keeps `flow.flow_timer`/`expires` updated from the 2xx so
/// the flow loop can re-derive its deadlines.
pub async fn refresh(
    sess: &mut crate::uac::Session,
    ep: &Endpoint,
    auth: &mut dyn TrunkAuth,
    flow: &mut Flow,
) -> Result<(), String> {
    let uri = ep.aor.clone();
    let mut extra: Vec<(String, String)> = Vec::new();
    auth.sign_request(Method::Register, &uri, &mut extra);
    flow.cseq += 1;
    send(sess, ep, &uri, flow, &extra).await?;
    let mut resp = recv_response(sess).await?;

    let mut rounds = 0u32;
    while (resp.code == 401 || resp.code == 407) && rounds < MAX_CHALLENGE_ROUNDS {
        rounds += 1;
        let www = resp.headers.get("WWW-Authenticate").map(str::to_string);
        let proxy = resp.headers.get("Proxy-Authenticate").map(str::to_string);
        match auth.on_challenge(resp.code, www.as_deref(), proxy.as_deref()) {
            ChallengeOutcome::Retry => {
                let Some((name, value)) = auth.pending_header() else {
                    return Err("trunk auth returned Retry without a credential header".into());
                };
                flow.cseq += 1;
                send(sess, ep, &uri, flow, &[(name, value)]).await?;
                resp = recv_response(sess).await?;
            }
            ChallengeOutcome::Fail(reason) => {
                return Err(format!("trunk REGISTER refresh auth failed: {reason}"));
            }
        }
    }
    if !(200..300).contains(&resp.code) {
        return Err(format!(
            "trunk REGISTER refresh rejected with {}",
            resp.code
        ));
    }
    flow.flow_timer = resp
        .headers
        .get("Flow-Timer")
        .and_then(|v| v.trim().parse::<u64>().ok());
    flow.expires = response_expires(&resp, &ep.contact).unwrap_or(flow.expires);
    tracing::debug!("trunk REGISTER refresh OK (cseq {})", flow.cseq);
    Ok(())
}

/// Granted expiry from a 200 OK: prefers the `;expires=` on OUR Contact
/// (multi-binding responses are normal once instances/GRUUs exist), then
/// any Contact expires, then the legacy `Expires` header. None = use what
/// we asked for.
fn response_expires(resp: &sip_core::message::Response, own_contact: &str) -> Option<u32> {
    let contacts: Vec<&str> = resp.headers.get_all("Contact").to_vec();
    let expiry = |c: &str| {
        c.split(';')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("expires="))
            .and_then(|v| v.trim().parse::<u32>().ok())
    };
    for c in &contacts {
        if c.contains(own_contact) {
            if let Some(e) = expiry(c) {
                return Some(e);
            }
        }
    }
    for c in &contacts {
        if let Some(e) = expiry(c) {
            return Some(e);
        }
    }
    resp.headers
        .get("Expires")
        .and_then(|v| v.trim().parse::<u32>().ok())
}

#[allow(clippy::too_many_arguments)]
async fn send(
    sess: &mut crate::uac::Session,
    ep: &Endpoint,
    uri: &str,
    flow: &Flow,
    extra: &[(String, String)],
) -> Result<(), String> {
    let mut all: Vec<(String, String)> = extra.to_vec();
    // RFC 5626 §9: clients supporting Outbound include `outbound` in
    // Supported on every registration; `gruu` (RFC 5627) rides along so
    // the registrar can publish pub-gruus for this AOR.
    all.push(("Supported".to_string(), "outbound, gruu".to_string()));
    all.push(("Expires".to_string(), flow.expires.to_string()));
    let reg = request(
        Method::Register,
        uri,
        ep,
        &sess.via(),
        &flow.call_id,
        flow.cseq,
        &flow.from_tag,
        None,
        true,
        &all,
    )?;
    tracing::info!(
        "trunk REGISTER {uri} (cseq {}, call-id {})",
        flow.cseq,
        flow.call_id
    );
    sess.send_msg(&SipMessage::Request(reg)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_is_half_expiry_with_floor() {
        let f = |expires: u32| Flow {
            call_id: "c".into(),
            from_tag: "t".into(),
            cseq: 1,
            flow_timer: None,
            expires,
        };
        assert_eq!(f(3600).refresh_interval_secs(), 1800);
        assert_eq!(f(4).refresh_interval_secs(), 2);
        assert_eq!(f(1).refresh_interval_secs(), 1, "floor keeps the loop sane");
        assert_eq!(f(0).refresh_interval_secs(), 1);
    }

    #[test]
    fn response_expires_prefers_contact_param_over_header() {
        // Build a minimal 200 OK wire form and mine it.
        let wire = "SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/TCP 10.0.0.9:5060;branch=z9hG4bKreg\r\n\
                    From: <sip:trunk@pbx>;tag=a\r\n\
                    To: <sip:trunk@pbx>;tag=b\r\n\
                    Call-ID: c@x\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Contact: <sip:trunk@10.0.0.9>;expires=118\r\n\
                    Contact: <sip:other@10.0.0.9>;expires=44\r\n\
                    Expires: 999\r\n\
                    Content-Length: 0\r\n\r\n";
        let msg = sip_core::parse_message(wire.as_bytes()).expect("parses");
        let resp = match msg {
            SipMessage::Response(r) => r,
            SipMessage::Request(_) => panic!("expected response"),
        };
        assert_eq!(
            response_expires(&resp, "sip:trunk@10.0.0.9"),
            Some(118),
            "our Contact wins"
        );
    }

    #[test]
    fn response_expires_falls_back_to_expires_header() {
        let wire = "SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKreg\r\n\
                    From: <sip:trunk@pbx>;tag=a\r\n\
                    To: <sip:trunk@pbx>;tag=b\r\n\
                    Call-ID: c@x\r\n\
                    CSeq: 1 REGISTER\r\n\
                    Expires: 300\r\n\
                    Content-Length: 0\r\n\r\n";
        let msg = sip_core::parse_message(wire.as_bytes()).expect("parses");
        let resp = match msg {
            SipMessage::Response(r) => r,
            SipMessage::Request(_) => panic!("expected response"),
        };
        assert_eq!(response_expires(&resp, "sip:trunk@10.0.0.9"), Some(300));
    }
}

#[cfg(test)]
mod flow_tests {
    use crate::config::Config;
    use crate::trunk::{register, Endpoint};
    use sip_core::message::SipMessage;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Reads one SIP message off the stream, skipping the leading CRLF
    /// pairs that RFC 5626 flow keep-alives look like (same as the server
    /// transport does).
    async fn read_sip(sock: &mut TcpStream) -> sip_core::Request {
        let mut acc: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Ok((msg, used)) = sip_core::parse_stream(&acc) {
                acc.drain(..used);
                match msg {
                    SipMessage::Request(r) => return r,
                    SipMessage::Response(_) => panic!("server read a response"),
                }
            }
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
                .await
                .expect("server read timed out")
                .expect("read error");
            if n == 0 {
                panic!("client closed the connection");
            }
            acc.extend_from_slice(&buf[..n]);
        }
    }

    fn ok_response(req: &sip_core::Request, flow_timer: &str, expires: u32) -> Vec<u8> {
        let resp = format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             From: {from}\r\n\
             To: {to};tag=zrtc-reg-server\r\n\
             Call-ID: {cid}\r\n\
             CSeq: {cseq}\r\n\
             Contact: <sip:trunk@127.0.0.1>;expires={expires}\r\n\
             Flow-Timer: {flow_timer}\r\n\
             Supported: outbound, gruu\r\n\
             Content-Length: 0\r\n\r\n",
            via = req.headers.get_all("Via")[0],
            from = req.headers.get("From").unwrap_or(""),
            to = req.headers.get("To").unwrap_or(""),
            cid = req.headers.call_id().unwrap_or(""),
            cseq = {
                let c = req.headers.cseq().unwrap();
                format!("{} REGISTER", c.seq)
            },
        );
        resp.into_bytes()
    }

    // RFC 5626 end-to-end on one TCP flow: REGISTER (Supported: outbound,
    // gruu, +sip.instance contact) → 200 with Flow-Timer → CRLF flow
    // keep-alive within the timer → REGISTER refresh on the SAME Call-ID
    // with CSeq+1 → 200. This is the exact cadence the daemon's flow loop
    // drives in production.
    #[tokio::test]
    async fn flow_loop_pings_and_refreshes_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Initial REGISTER.
            let req1 = read_sip(&mut sock).await;
            assert_eq!(req1.headers.cseq().unwrap().seq, 1);
            // Outbound negotiation material on the wire.
            assert!(
                req1.headers
                    .get("Contact")
                    .unwrap_or("")
                    .contains("+sip.instance=\"urn:uuid:test-inst\""),
                "instance contact sent: {:?}",
                req1.headers.get("Contact")
            );
            assert_eq!(
                req1.headers.get("Supported"),
                Some("outbound, gruu"),
                "RFC 5626/5627 option tags advertised"
            );
            sock.write_all(&ok_response(&req1, "1", 4)).await.unwrap();

            // CRLF flow keep-alive (the ping must be its own write).
            let mut buf = [0u8; 16];
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
                .await
                .expect("no flow keep-alive within 5s")
                .expect("read error");
            assert_eq!(
                &buf[..n],
                b"\r\n\r\n",
                "TCP flow keep-alive is a double CRLF (RFC 5626 §4.4)"
            );

            // Refresh: same Call-ID, CSeq incremented.
            let req2 = read_sip(&mut sock).await;
            assert_eq!(
                req2.headers.call_id().map(str::to_string),
                req1.headers.call_id().map(str::to_string),
                "refresh reuses the registration Call-ID"
            );
            assert_eq!(req2.headers.cseq().unwrap().seq, 2);
            sock.write_all(&ok_response(&req2, "1", 4)).await.unwrap();
        });

        let toml_src = format!(
            "[trunk]\naddress = \"127.0.0.1:{}\"\ntransport = \"tcp\"\nregister = true\ninstance_id = \"urn:uuid:test-inst\"\nkeepalive_secs = 300\n",
            addr.port()
        );
        let cfg: Config = toml::from_str(&toml_src).expect("test config");
        let ep = Endpoint::from_config(&cfg).expect("endpoint resolves (IP literal)");
        let mut sess = crate::uac::Session::connect(&crate::uac::UacOpts {
            target: ep.target,
            transport: crate::uac::Transport::Tcp,
            ..Default::default()
        })
        .await
        .expect("client connect");
        let mut auth = crate::auth::build(&cfg.trunk).expect("ip auth mode");
        let flow = register::run(&mut sess, &ep, auth.as_mut(), 4)
            .await
            .expect("initial REGISTER");
        assert_eq!(flow.flow_timer, Some(1), "Flow-Timer mined from the 2xx");
        assert_eq!(flow.expires, 4, "granted expiry mined from the 2xx");

        // Drive the real loop; the server task asserts ping + refresh.
        // Join the SERVER first — aborting the loop before it fires the
        // ping/refresh would race the assertions.
        let handle = tokio::spawn(crate::trunk::flow_loop(sess, ep, auth, flow));
        server.await.expect("server task panicked");
        handle.abort();
    }
}
