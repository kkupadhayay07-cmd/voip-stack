//! The B2BUA engine loop: SIP handling (UAS + UAC legs), call lifecycle and
//! pump orchestration. Single-owner state (no locks on the call map).

use crate::media::{self, PumpConfig, PumpHandle};
use crate::rel100::{self, Reliable1xx};
use crate::sdp_util;
use crate::timers::{self, LegTimers, Role, UasNegotiation};
use crate::webrtc;
use crate::{datachan, CdrEvent, Side};
use rand::Rng;
use sdp::negotiate::{stream_plans, StreamPlan};
use sip_core::builder::RequestBuilder;
use sip_core::headers::Refresher;
use sip_core::ids::{new_branch, new_call_id, new_tag};
use sip_core::message::{Method, Request, Response, SipMessage};
use sip_core::uri::{Host, SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use sip_tx::{
    ClientInviteTx, ServerInviteTx, Transport as TxTransport, TxAction, TxEvent, TxState,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

/// One dial-plan route: longest-prefix match on the INVITE request-URI user.
#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: String,
    pub target: String,
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct B2buaConfig {
    /// SIP/UDP bind address (e.g. `0.0.0.0:5060`).
    pub sip_bind: SocketAddr,
    /// Host advertised in SDP `c=` lines and the local identity.
    pub media_host: String,
    /// Base for media port allocation (0 → OS-assigned ephemeral).
    pub media_base_port: u16,
    /// Codecs offered/answered, in preference order.
    pub codecs: Vec<codecs::CodecId>,
    /// Dial-plan routes.
    pub routes: Vec<Route>,
    /// Fallback target URI when no route prefix matches.
    pub default_target: String,
    /// Smallest accepted session interval; smaller `Session-Expires` values
    /// are answered with 422 carrying this as `Min-SE` (RFC 4028 §5).
    pub session_timer_min_se: u64,
}

impl Default for B2buaConfig {
    fn default() -> Self {
        Self {
            sip_bind: "0.0.0.0:5060".parse().unwrap(),
            media_host: "127.0.0.1".into(),
            media_base_port: 0,
            codecs: vec![
                codecs::CodecId::Pcmu,
                codecs::CodecId::Pcma,
                codecs::CodecId::G722,
                codecs::CodecId::G729,
                codecs::CodecId::Opus,
            ],
            routes: Vec::new(),
            default_target: "sip:b2bua@127.0.0.1:5062".into(),
            session_timer_min_se: timers::DEFAULT_MIN_SE,
        }
    }
}

const TICK: Duration = Duration::from_millis(200);
/// RFC 3261 Timer H budget: how long we wait for the ACK that confirms a
/// 2xx before declaring the dialog dead (64·T1).
const ACK_TIMEOUT: Duration = Duration::from_millis(64 * 500);

/// The engine's local listen address, used as the Via sent-by on requests we
/// originate (a remote peer's address must never appear as OUR sent-by).
static ENGINE_VIA: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();

/// Via sent-by text for engine-originated requests: bare IP when the port is
/// 5060, `ip:port` otherwise.
fn via_sent_by() -> String {
    match ENGINE_VIA.get() {
        Some(a) if a.port() == 5060 => a.ip().to_string(),
        Some(a) => a.to_string(),
        // Direct construction without run_on (unit tests): loopback default.
        None => "127.0.0.1".into(),
    }
}

struct Leg {
    call_id: String,
    local_tag: String,
    remote_tag: Option<String>,
    remote_sip: SocketAddr,
    /// Next CSeq we send in this dialog (our own UAC-side space: leg-B
    /// refresh/BYE, leg-A UAS-originated in-dialog requests).
    next_cseq: u32,
    /// Leg A: the INVITE we received (source for responses).
    invite: Option<Request>,
    /// Peer Contact URI text (request-URI for in-dialog requests).
    contact: Option<String>,
    plan: Option<StreamPlan>,
    /// Bound RTP socket (A: bound on INVITE or handed over by the WebRTC
    /// establishment once ICE+DTLS complete, B: bound on originate).
    rtp: Option<Arc<UdpSocket>>,
    media: Option<PumpHandle>,
    confirmed: bool,
    /// RFC 4028 session-timer state (engaged legs only).
    timer: Option<LegTimers>,
    /// RFC 3262 (UAC side): the PRACK we sent for the last reliable 1xx.
    /// A retransmitted 1xx (same `RSeq`) must be answered by RESENDING it
    /// verbatim — same CSeq number and same branch (RFC 3261 §17.1.2).
    last_prack: Option<SentPrack>,
    /// Prepared ICE+DTLS transport when this leg negotiated
    /// UDP/TLS/RTP/SAVPF (leg A only today).  `rtp` is None until
    /// [`webrtc::WebRtcMedia::establish`] hands the agent socket over.
    webrtc: Option<webrtc::WebRtcMedia>,
    /// Data-channel engine on this leg's established DTLS transport
    /// (RFC 8261). Present only when the offer carried an
    /// `m=application UDP/DTLS/SCTP` m-line and the leg came up.
    dc: Option<datachan::DataChannelHandle>,
}

/// The PRACK a leg last sent for a reliable 1xx, kept as exact wire bytes
/// so a retransmitted 1xx is answered byte-identically.
struct SentPrack {
    rseq: u32,
    bytes: Vec<u8>,
}

/// Which INVITE the leg-B client transaction slot currently carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BInviteKind {
    /// The initial call-setup INVITE.
    Dial,
    /// A session-timer refresh re-INVITE (RFC 4028 §7.2).
    Refresh,
}

struct Call {
    leg_a: Option<Leg>,
    leg_b: Option<Leg>,
    /// Leg B client INVITE transaction (RFC 3261 §17.1.1): Timer A/B/D.
    /// Carries the dial INVITE first, then session-refresh re-INVITEs.
    b_tx: Option<ClientInviteTx>,
    /// Which INVITE the `b_tx` slot carries right now.
    b_tx_kind: BInviteKind,
    /// Leg A server INVITE transaction (RFC 3261 §17.2.1): Timer G/H/I.
    /// Gone after the 2xx — the ACK for a 2xx is dialog-level (§17.2.3).
    a_tx: Option<ServerInviteTx>,
    /// Leg A client INVITE transaction for our own refresh re-INVITE
    /// (used when we are the leg-A refresher, RFC 4028 §7.2).
    a_out_tx: Option<ClientInviteTx>,
    /// SDP answer for leg A (sent with the 200).
    a_answer: String,
    /// Remote SCTP port (RFC 8841) when the leg-A answer accepted an
    /// `m=application` data channel — the data-channel engine spawns on the
    /// established DTLS transport in `confirm_leg_a`.
    a_dc_port: Option<u16>,
    /// The offer we put on leg B (resent for no-change refreshes and
    /// 422 retries).
    b_offer: String,
    /// The interval we requested on leg B (422-retry arithmetic, §7).
    b_se: Option<u64>,
    /// RFC 3262 (leg A, UAS side): our reliable 1xx awaiting the caller's
    /// PRACK, with the serialized response for retransmission.
    a_rel: Option<AwaitPrack>,
    /// RFC 3262 §3: leg B answered while the reliable 1xx is unacknowledged
    /// — the final 200 to leg A is parked until the PRACK arrives.
    a_hold: bool,
    /// Last RSeq we acknowledged with a 200 to a PRACK (idempotent re-answer
    /// for retransmitted PRACKs whose first 200 was lost).
    a_prack_acked: Option<u32>,
    /// A 421 (`Require: 100rel`) retry was already attempted on the dial.
    b_421_retried: bool,
    /// Deadline for the caller's ACK after we sent the 200 (Timer H is gone
    /// with the transaction; without this a dead caller leaks the call and
    /// both media pumps forever).
    a_ack_deadline: Option<Instant>,
    created: Instant,
}

/// Leg-A reliable provisional response awaiting its PRACK (RFC 3262 §5).
struct AwaitPrack {
    state: Reliable1xx,
    /// Exact bytes of the response as first sent (retransmitted verbatim).
    bytes: Vec<u8>,
}

impl Call {
    fn new(a_answer: String, b_offer: String) -> Self {
        Self {
            leg_a: None,
            leg_b: None,
            b_tx: None,
            b_tx_kind: BInviteKind::Dial,
            a_tx: None,
            a_out_tx: None,
            a_answer,
            a_dc_port: None,
            b_offer,
            b_se: None,
            a_rel: None,
            a_hold: false,
            a_prack_acked: None,
            b_421_retried: false,
            a_ack_deadline: None,
            created: Instant::now(),
        }
    }
}

/// The running engine. Drive it with [`B2bua::run`].
pub struct B2bua {
    cfg: B2buaConfig,
    cdr: UnboundedSender<CdrEvent>,
}

impl B2bua {
    pub fn new(cfg: B2buaConfig, cdr: UnboundedSender<CdrEvent>) -> Self {
        Self { cfg, cdr }
    }

    /// Runs the engine forever. Binds SIP and begins dispatching.
    pub async fn run(self) -> std::io::Result<()> {
        let sock = Arc::new(UdpSocket::bind(self.cfg.sip_bind).await?);
        self.run_on(sock).await
    }

    /// Runs the engine on a pre-bound socket (tests, shared listeners).
    pub async fn run_on(self, sock: Arc<UdpSocket>) -> std::io::Result<()> {
        self.install_sink();
        let local = sock.local_addr()?;
        let _ = ENGINE_VIA.set(local);
        tracing::info!(%local, "b2bua engine listening");

        let mut buf = vec![0u8; 65_535];
        let mut calls: HashMap<String, Call> = HashMap::new();
        let mut b_to_a: HashMap<String, String> = HashMap::new();
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let (n, src) = match r {
                        Ok(x) => x,
                        Err(e) => { tracing::warn!("sip recv err: {e}"); continue; }
                    };
                    let msg = match parse_message(&buf[..n]) {
                        Ok(m) => m,
                        Err(e) => { tracing::debug!("unparseable SIP from {src}: {e}"); continue; }
                    };
                    self.dispatch(&sock, local, &mut calls, &mut b_to_a, msg, src).await;
                }
                _ = ticker.tick() => {
                    self.timers(&sock, &mut calls, &mut b_to_a).await;
                }
            }
        }
    }

    /// Drives transaction timers and the RFC 4028 session-refresh clocks.
    async fn timers(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
    ) {
        let now = Instant::now();

        // Phase 1: drive every transaction whose deadline has passed and
        // read the per-leg timer clocks. The state machines are pure;
        // phase 2 performs the I/O and the call-level consequences.
        struct Due {
            sends: Vec<(Vec<u8>, SocketAddr)>,
            dial_b_failed: bool,
            refresh_b_failed: bool,
            refresh_a_failed: bool,
            expired: bool,
            prack_gave_up: bool,
            ack_timeout: bool,
        }
        let mut due: Vec<(String, Due)> = Vec::new();
        for (id, c) in calls.iter_mut() {
            let mut d = Due {
                sends: Vec::new(),
                dial_b_failed: false,
                refresh_b_failed: false,
                refresh_a_failed: false,
                expired: false,
                prack_gave_up: false,
                ack_timeout: false,
            };

            // Leg B: client INVITE transaction — Timer A retransmissions,
            // Timer B total timeout, Timer D cleanup. The same slot carries
            // session-refresh re-INVITEs once the call is up.
            let b_kind = c.b_tx_kind;
            if let Some(tx) = c.b_tx.as_mut() {
                while let Some(dl) = tx.next_deadline() {
                    if now < dl {
                        break;
                    }
                    let pre = tx.state();
                    for act in tx.on_event(TxEvent::Timeout, now) {
                        match act {
                            TxAction::SendRequest(r) => {
                                if let Some(b) = &c.leg_b {
                                    d.sends
                                        .push((serialize(&SipMessage::Request(r)), b.remote_sip));
                                }
                            }
                            TxAction::DeleteTransaction
                                if matches!(pre, TxState::Trying | TxState::Proceeding) =>
                            {
                                if b_kind == BInviteKind::Dial {
                                    d.dial_b_failed = true;
                                } else {
                                    d.refresh_b_failed = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    if tx.state() == TxState::Terminated {
                        c.b_tx = None;
                        break;
                    }
                }
            }

            // Leg A: server INVITE transaction — Timer G final-response
            // retransmissions, Timer H (no ACK) and Timer I dwell.
            if let Some(tx) = c.a_tx.as_mut() {
                while let Some(dl) = tx.next_deadline() {
                    if now < dl {
                        break;
                    }
                    for act in tx.on_event(TxEvent::Timeout, now) {
                        if let TxAction::SendResponse(r) = act {
                            if let Some(a) = &c.leg_a {
                                d.sends
                                    .push((serialize(&SipMessage::Response(r)), a.remote_sip));
                            }
                        }
                    }
                    if tx.state() == TxState::Terminated {
                        c.a_tx = None;
                        break;
                    }
                }
            }

            // Leg A: our own refresh re-INVITE transaction (we are the
            // leg-A refresher, RFC 4028 §7.2).
            if let Some(a) = c.leg_a.as_ref() {
                if let Some(tx) = c.a_out_tx.as_mut() {
                    let dst = a.remote_sip;
                    while let Some(dl) = tx.next_deadline() {
                        if now < dl {
                            break;
                        }
                        let pre = tx.state();
                        for act in tx.on_event(TxEvent::Timeout, now) {
                            match act {
                                TxAction::SendRequest(r) => {
                                    d.sends.push((serialize(&SipMessage::Request(r)), dst));
                                }
                                TxAction::DeleteTransaction
                                    if matches!(pre, TxState::Trying | TxState::Proceeding) =>
                                {
                                    d.refresh_a_failed = true;
                                }
                                _ => {}
                            }
                        }
                        if tx.state() == TxState::Terminated {
                            c.a_out_tx = None;
                            break;
                        }
                    }
                }
            }

            // RFC 4028 clocks: refresh at half the interval when we are the
            // refresher (§9), teardown when a leg lets the clock run out
            // (§10).
            if let Some(a) = c.leg_a.as_mut() {
                match leg_timer_action(a, now) {
                    Some(TimerAction::Refresh) => {
                        let cseq = take_cseq(a);
                        let body = a
                            .invite
                            .as_ref()
                            .map(|i| i.body.clone())
                            .unwrap_or_default();
                        if let Some(t) = a.timer.as_mut() {
                            t.pending = Some(cseq);
                        }
                        let invite = refresh_reinvite(a, cseq, true, body);
                        let mut tx = ClientInviteTx::new(invite, TxTransport::Udp);
                        for act in tx.on_event(TxEvent::Send, Instant::now()) {
                            if let TxAction::SendRequest(r) = act {
                                d.sends
                                    .push((serialize(&SipMessage::Request(r)), a.remote_sip));
                            }
                        }
                        c.a_out_tx = Some(tx);
                        tracing::debug!(call_id = %id, "leg A session refresh due (cseq {cseq})");
                    }
                    Some(TimerAction::Expired) => d.expired = true,
                    None => {}
                }
            }
            if c.b_tx.is_none() {
                if let Some(b) = c.leg_b.as_mut() {
                    match leg_timer_action(b, now) {
                        Some(TimerAction::Refresh) => {
                            let cseq = take_cseq(b);
                            let body = c.b_offer.clone().into_bytes();
                            if let Some(t) = b.timer.as_mut() {
                                t.pending = Some(cseq);
                            }
                            let invite = refresh_reinvite(b, cseq, false, body);
                            let mut tx = ClientInviteTx::new(invite, TxTransport::Udp);
                            for act in tx.on_event(TxEvent::Send, Instant::now()) {
                                if let TxAction::SendRequest(r) = act {
                                    d.sends
                                        .push((serialize(&SipMessage::Request(r)), b.remote_sip));
                                }
                            }
                            c.b_tx = Some(tx);
                            c.b_tx_kind = BInviteKind::Refresh;
                            tracing::debug!(call_id = %id, "leg B session refresh due (cseq {cseq})");
                        }
                        Some(TimerAction::Expired) => d.expired = true,
                        None => {}
                    }
                }
            }

            // RFC 3262 §5: retransmit the leg-A reliable 1xx with
            // Timer-G-style backoff until its PRACK arrives; §3 allows
            // abandoning the dialog attempt after 64·T1.
            if let Some(rel) = c.a_rel.as_mut() {
                if rel.state.retransmit_due(now) {
                    if let Some(a) = c.leg_a.as_ref() {
                        rel.state.advance(now);
                        d.sends.push((rel.bytes.clone(), a.remote_sip));
                    }
                }
                if rel.state.give_up(now) {
                    d.prack_gave_up = true;
                }
            }

            // Timer H equivalent at dialog level: a 2xx we sent (confirm_leg_a
            // took the server transaction, which owned the old Timer H) must
            // still be ACKed within 64·T1 or the caller is gone.
            if let Some(dl) = c.a_ack_deadline {
                let confirmed = c.leg_a.as_ref().map(|a| a.confirmed).unwrap_or(false);
                if !confirmed && now >= dl {
                    d.ack_timeout = true;
                }
            }

            if !d.sends.is_empty()
                || d.dial_b_failed
                || d.refresh_a_failed
                || d.refresh_b_failed
                || d.expired
                || d.prack_gave_up
                || d.ack_timeout
            {
                due.push((id.clone(), d));
            }
        }

        // Phase 2: execute the actions.
        for (id, d) in due {
            for (bytes, dst) in d.sends {
                let sock = sock.clone();
                tokio::spawn(async move {
                    let _ = sock.send_to(&bytes, dst).await;
                });
            }
            if d.dial_b_failed {
                tracing::warn!(call_id = %id, "outgoing INVITE timed out (Timer B)");
                if let Some(c) = calls.get_mut(&id) {
                    c.b_tx = None;
                    if let Some(a) = &c.leg_a {
                        if let Some(invite) = &a.invite {
                            let resp = sip_core::builder::respond_to(
                                invite,
                                504,
                                "Server Time-out",
                                Vec::new(),
                                None,
                            );
                            let bytes = serialize(&SipMessage::Response(resp));
                            let sock = sock.clone();
                            let dst = a.remote_sip;
                            tokio::spawn(async move {
                                let _ = sock.send_to(&bytes, dst).await;
                            });
                        }
                    }
                }
                teardown(calls, b_to_a, &id, "Timer B", None);
            }
            if d.refresh_a_failed || d.refresh_b_failed {
                tracing::warn!(call_id = %id, "session refresh timed out (Timer B)");
                if let Some(c) = calls.get_mut(&id) {
                    // The refresh is dead on the failed leg; per RFC 4028
                    // §11 the session is over — end the other leg too.
                    if d.refresh_b_failed {
                        if let Some(a) = c.leg_a.as_mut() {
                            Self::send_bye(sock, a).await;
                        }
                    } else if let Some(b) = c.leg_b.as_mut() {
                        Self::send_bye(sock, b).await;
                    }
                }
                teardown(calls, b_to_a, &id, "session refresh failed", None);
            }
            if d.expired {
                tracing::info!(call_id = %id, "session timer expired (RFC 4028 §10)");
                if let Some(c) = calls.get_mut(&id) {
                    if let Some(a) = c.leg_a.as_mut() {
                        Self::send_bye(sock, a).await;
                    }
                    if let Some(b) = c.leg_b.as_mut() {
                        Self::send_bye(sock, b).await;
                    }
                }
                teardown(calls, b_to_a, &id, "session timer expired", None);
            }
            if d.prack_gave_up {
                tracing::warn!(
                    call_id = %id,
                    "PRACK never arrived; abandoning dialog attempt (RFC 3262 §3)"
                );
                if let Some(c) = calls.get_mut(&id) {
                    // Final 503 to A through the still-open server
                    // transaction; BYE to B if the dial already completed.
                    let fail: Option<(Response, SocketAddr)> = c.leg_a.as_ref().and_then(|a| {
                        a.invite.as_ref().map(|invite| {
                            (
                                sip_core::builder::respond_to(
                                    invite,
                                    503,
                                    "Service Unavailable",
                                    Vec::new(),
                                    Some(&a.local_tag),
                                ),
                                a.remote_sip,
                            )
                        })
                    });
                    if let Some((resp, dst)) = fail {
                        if let Some(mut a_tx) = c.a_tx.take() {
                            send_staged(&mut a_tx, sock, dst, resp).await;
                        } else {
                            let bytes = serialize(&SipMessage::Response(resp));
                            let _ = sock.send_to(&bytes, dst).await;
                        }
                    }
                    if c.leg_b.as_ref().map(|b| b.confirmed).unwrap_or(false) {
                        if let Some(b) = c.leg_b.as_mut() {
                            Self::send_bye(sock, b).await;
                        }
                    } else if let Some(b_tx) = c.b_tx.as_ref() {
                        // Leg B is still ringing: CANCEL the outstanding
                        // dial INVITE (§9.1) so it does not answer into a
                        // dead call (and so its CSeq/Via state stays sane).
                        if let Some(b) = c.leg_b.as_ref() {
                            let cancel = build_cancel(b_tx.request());
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Request(cancel)), b.remote_sip)
                                .await;
                        }
                    }
                }
                teardown(calls, b_to_a, &id, "PRACK never arrived", None);
            }
            if d.ack_timeout {
                tracing::warn!(call_id = %id, "no ACK after 200 (Timer H, dialog level)");
                if let Some(c) = calls.get_mut(&id) {
                    if let Some(b) = c.leg_b.as_mut() {
                        Self::send_bye(sock, b).await;
                    }
                }
                teardown(calls, b_to_a, &id, "no ACK after 200", None);
            }
        }
    }

    async fn dispatch(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        msg: SipMessage,
        src: SocketAddr,
    ) {
        match msg {
            SipMessage::Request(req) => {
                let Some(call_id) = req.headers.get("Call-ID").map(str::to_string) else {
                    return;
                };
                match req.method {
                    Method::Invite => {
                        self.on_invite(sock, local, calls, b_to_a, req, call_id, src)
                            .await;
                    }
                    Method::Ack => self.on_ack(calls, &req, &call_id),
                    Method::Bye => self.on_bye(sock, calls, b_to_a, &req, call_id, src).await,
                    Method::Cancel => {
                        self.on_cancel(sock, calls, b_to_a, &req, call_id, src)
                            .await;
                    }
                    Method::Update => {
                        self.on_update(sock, calls, b_to_a, &req, &call_id, src)
                            .await;
                    }
                    Method::Prack => {
                        self.on_prack(sock, local, calls, b_to_a, &req, &call_id, src)
                            .await;
                    }
                    Method::Options => {
                        let resp = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(resp)), src)
                            .await;
                    }
                    _ => {
                        let resp = sip_core::builder::respond_to(
                            &req,
                            501,
                            "Not Implemented",
                            Vec::new(),
                            None,
                        );
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(resp)), src)
                            .await;
                    }
                }
            }
            SipMessage::Response(resp) => {
                let Some(call_id) = resp.headers.get("Call-ID").map(str::to_string) else {
                    return;
                };
                let Some(a_id) = b_to_a.get(&call_id).cloned() else {
                    // Not a leg-B dialog. The only responses we receive on a
                    // leg-A Call-ID are answers to our own in-dialog requests
                    // (currently the session-refresh re-INVITE).
                    self.on_a_refresh_response(sock, calls, b_to_a, &call_id, resp)
                        .await;
                    return;
                };
                let class = resp.code / 100;
                // Only INVITE responses may enter the INVITE transaction
                // slot: a 200 for our PRACK (or a BYE response) carries a
                // different CSeq method and must not be mistaken for call
                // setup (§17.1.1.2 matches responses to the INVITE only).
                if let Some(m) = resp.headers.cseq().map(|c| c.method) {
                    if !m.is_invite() {
                        return;
                    }
                }
                let Some(call) = calls.get_mut(&a_id) else {
                    return;
                };
                let kind = call.b_tx_kind;
                // Drive the leg-B client INVITE transaction (§17.1.1): 1xx
                // stops Timer A, finals move to Completed (and generate the
                // ACK for non-2xx), 2xx terminates it.
                let mut passed: Vec<Response> = Vec::new();
                let mut ack: Option<(Vec<u8>, SocketAddr)> = None;
                let mut had_tx = false;
                if let Some(tx) = call.b_tx.as_mut() {
                    had_tx = true;
                    let dst = call.leg_b.as_ref().map(|b| b.remote_sip);
                    for act in tx.on_event(TxEvent::Received(resp.clone()), Instant::now()) {
                        match act {
                            TxAction::PassToTu(SipMessage::Response(r)) => passed.push(r),
                            TxAction::SendRequest(r) => {
                                if let Some(dst) = dst {
                                    ack = Some((serialize(&SipMessage::Request(r)), dst));
                                }
                            }
                            _ => {}
                        }
                    }
                    if tx.state() == TxState::Terminated {
                        call.b_tx = None;
                    }
                }
                if let Some((bytes, dst)) = ack {
                    let _ = sock.send_to(&bytes, dst).await;
                }
                if !had_tx {
                    // Late 2xx retransmission: re-ACK with the CSeq of the
                    // INVITE the 200 belongs to (initial dial or refresh).
                    if class == 2 {
                        if let Some(b) = call.leg_b.as_ref() {
                            let cseq = resp.headers.cseq().map(|c| c.seq).unwrap_or(1);
                            self.send_ack(sock, b, cseq);
                        }
                    }
                    return;
                }
                for r in passed {
                    let class = r.code / 100;
                    if class == 1 {
                        // RFC 3262 §4: a reliable 1xx on the dial is
                        // answered with PRACK.
                        if kind == BInviteKind::Dial {
                            self.prack_leg_b_1xx(sock, calls, &a_id, &r).await;
                        }
                        continue;
                    }
                    if class == 2 {
                        match kind {
                            BInviteKind::Dial => {
                                self.on_b_answered(sock, local, calls, b_to_a, &a_id, &call_id, r)
                                    .await;
                            }
                            BInviteKind::Refresh => self.on_b_refreshed(sock, calls, &a_id, &r),
                        }
                    } else {
                        // 421 Extension Required on the initial dial: the
                        // peer insists on 100rel — retry once, merging the
                        // 421's `Require` tokens into `Supported` (RFC 3262 §3).
                        let retried = kind == BInviteKind::Dial
                            && r.code == 421
                            && self
                                .retry_b_421(sock, local, calls, &a_id, &call_id, &r)
                                .await;
                        if retried {
                            continue;
                        }
                        // 422 on the initial dial: retry with the peer's
                        // Min-SE (RFC 4028 §7) before giving up.
                        let retried = kind == BInviteKind::Dial
                            && r.code == 422
                            && self
                                .retry_b_422(sock, local, calls, &a_id, &call_id, &r)
                                .await;
                        if retried {
                            continue;
                        }
                        match kind {
                            BInviteKind::Dial => {
                                tracing::info!(call_id = %a_id, "leg B failed with {}", r.code);
                                if let Some(call) = calls.get_mut(&a_id) {
                                    if let Some(a) = call.leg_a.as_ref() {
                                        if let Some(invite) = &a.invite {
                                            let code = if class >= 5 { 503 } else { 486 };
                                            let reason = if class >= 5 {
                                                "Service Unavailable"
                                            } else {
                                                "Busy Here"
                                            };
                                            let fail = sip_core::builder::respond_to(
                                                invite,
                                                code,
                                                reason,
                                                Vec::new(),
                                                None,
                                            );
                                            let _ = sock
                                                .send_to(
                                                    &serialize(&SipMessage::Response(fail)),
                                                    a.remote_sip,
                                                )
                                                .await;
                                        }
                                    }
                                }
                                teardown(calls, b_to_a, &a_id, "leg B rejected", Some(r.code));
                            }
                            BInviteKind::Refresh => {
                                // Refresh refused: the session is over
                                // (RFC 4028 §11) — end the other leg too.
                                tracing::info!(
                                    call_id = %a_id,
                                    "leg B session refresh rejected with {}",
                                    r.code
                                );
                                if let Some(call) = calls.get_mut(&a_id) {
                                    if let Some(a) = call.leg_a.as_mut() {
                                        Self::send_bye(sock, a).await;
                                    }
                                }
                                teardown(
                                    calls,
                                    b_to_a,
                                    &a_id,
                                    "leg B session refresh failed",
                                    Some(r.code),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handles an inbound INVITE. Internal but takes the full per-call
    /// context; grouping into a struct would add indirection without value.
    #[allow(clippy::too_many_arguments)]
    async fn on_invite(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: Request,
        call_id: String,
        src: SocketAddr,
    ) {
        // In-dialog INVITE on leg B first: its Call-IDs are not top-level
        // keys of `calls`, so without this check it would fall through to
        // new-call creation.
        if b_to_a.contains_key(&call_id) {
            self.on_b_reinvite(sock, local, calls, b_to_a, req, &call_id, src)
                .await;
            return;
        }

        // Existing call: drive the leg-A server transaction with the
        // (possibly retransmitted) INVITE first (RFC 3261 §17.2.1).
        if let Some(c) = calls.get_mut(&call_id) {
            let mut handled = false;
            if let Some(a_tx) = c.a_tx.as_mut() {
                for act in a_tx.on_event(TxEvent::ReceivedRequest(req.clone()), Instant::now()) {
                    if let TxAction::SendResponse(r) = act {
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(r)), src)
                            .await;
                        handled = true;
                    }
                }
                if a_tx.state() == TxState::Terminated {
                    c.a_tx = None;
                }
            }
            if !handled {
                let branch = via_branch(&req);
                let known = c
                    .leg_a
                    .as_ref()
                    .and_then(|a| a.invite.as_ref())
                    .map(|invite| via_branch(invite) == branch)
                    .unwrap_or(false);
                if known {
                    // Post-2xx: retransmitted INVITE → resend the cached 200.
                    let resent = c.leg_a.as_ref().and_then(|a| {
                        let invite = a.invite.as_ref()?;
                        (via_branch(invite) == branch).then(|| {
                            let mut response = sip_core::builder::respond_to(
                                invite,
                                200,
                                "OK",
                                c.a_answer.clone().into_bytes(),
                                Some(&a.local_tag),
                            );
                            response
                                .headers
                                .add("Contact", format!("<sip:zrtc@{local}>"));
                            (serialize(&SipMessage::Response(response)), a.remote_sip)
                        })
                    });
                    if let Some((bytes, dst)) = resent {
                        let _ = sock.send_to(&bytes, dst).await;
                    }
                } else {
                    // A different branch: an in-dialog re-INVITE (session
                    // refresh, hold attempt, or glare).
                    self.on_a_reinvite(sock, c, &req, src, local).await;
                }
            }
            return;
        }

        // INVITE carrying a To tag but no known dialog: stale or spoofed —
        // RFC 3261 §12.2.2 answers 481 (initial INVITEs carry no To tag).
        if req.headers.to().and_then(|t| t.tag).is_some() {
            let resp = sip_core::builder::respond_to(
                &req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }

        // The leg-A server INVITE transaction owns every response we send
        // for this request (RFC 3261 §17.2.1).
        let mut a_tx = ServerInviteTx::new(req.clone(), TxTransport::Udp);

        // The leg-A dialog tag is decided up front: a reliable 1xx carries
        // it so the caller's PRACK can be routed back to this dialog.
        let a_tag = new_tag();
        // RFC 3262: the caller advertises 100rel support via `Supported` or
        // `Require` on the INVITE.
        let caller_rel100 =
            req.headers.supported().has("100rel") || req.headers.require().has("100rel");

        // RFC 4028 negotiation before anything else: a session interval
        // below our Min-SE is rejected with 422 (§5).
        let negotiation =
            timers::negotiate_uas(&req, self.cfg.session_timer_min_se, timers::DEFAULT_SE);
        if let UasNegotiation::TooSmall(min_se) = negotiation {
            tracing::info!(%call_id, "session interval below Min-SE: 422");
            // A final response to an initial request carries a fresh To tag
            // (RFC 3261 §8.2.6.2 — everything except 100 Trying).
            let mut resp = sip_core::builder::respond_to(
                &req,
                422,
                "Session Interval Too Small",
                Vec::new(),
                Some(&new_tag()),
            );
            resp.headers.add("Min-SE", min_se.to_string());
            resp.headers.add("Supported", "timer");
            send_staged(&mut a_tx, sock, src, resp).await;
            return;
        }

        // SDP offer required.
        let offer = match sdp::parse::parse(&String::from_utf8_lossy(&req.body)) {
            Ok(o) => o,
            Err(e) => {
                tracing::info!(%call_id, "INVITE without valid SDP: {e}");
                send_staged(
                    &mut a_tx,
                    sock,
                    src,
                    sip_core::builder::respond_to(
                        &req,
                        488,
                        "Not Acceptable Here",
                        Vec::new(),
                        None,
                    ),
                )
                .await;
                return;
            }
        };

        send_staged(
            &mut a_tx,
            sock,
            src,
            sip_core::builder::respond_to(&req, 100, "Trying", Vec::new(), None),
        )
        .await;

        // WebRTC detection (RFC 5763/5764): a secure-proto m-line —
        // UDP/TLS/RTP/SAVPF media or UDP/DTLS/SCTP data channels (RFC 8841)
        // — with a DTLS fingerprint (m-line or session level) runs the leg
        // over ICE → DTLS → SRTP instead of plaintext RTP.  On a WebRTC
        // offer we do NOT bind a plain socket — the ICE agent's socket IS
        // the media socket and its port goes into the answer.
        let webrtc_offer = offer.medias.iter().any(|m| {
            (m.proto == "UDP/TLS/RTP/SAVPF" || m.proto == "UDP/DTLS/SCTP")
                && (m.fingerprint.is_some() || offer.fingerprint.is_some())
        });
        // The media transport negotiates on the (first) RTP m-line; a pure
        // data-channel offer falls back to the first m-line (an application
        // m-line carries the same ICE/DTLS fields).
        let offer_media = offer
            .medias
            .iter()
            .find(|m| m.proto == "UDP/TLS/RTP/SAVPF")
            .or_else(|| offer.medias.first())
            .cloned();
        // RFC 8841 data-channel negotiation: the offer's application m-line
        // (and its `a=sctp-port`, defaulting per RFC 8841 §4.1 to 5000).
        let dc_offer = offer
            .medias
            .iter()
            .any(|m| m.media == "application" && m.proto == "UDP/DTLS/SCTP" && m.port != 0);
        let remote_sctp_port = offer
            .medias
            .iter()
            .filter(|m| m.media == "application")
            .find_map(|m| {
                m.attributes
                    .iter()
                    .find(|a| a.name == "sctp-port")
                    .and_then(|a| a.value.as_deref())
                    .and_then(|v| v.parse::<u16>().ok())
            })
            .unwrap_or(datachan::DEFAULT_SCTP_PORT);
        let (a_sock, a_webrtc, a_port) = if webrtc_offer {
            let m = offer_media.as_ref().expect("checked above");
            match webrtc::WebRtcMedia::prepare(m).await {
                Ok(w) => {
                    let port = w.local_port().unwrap_or(0);
                    (None, Some(w), port)
                }
                Err(e) => {
                    tracing::info!(%call_id, "WebRTC transport rejected: {e}");
                    send_staged(
                        &mut a_tx,
                        sock,
                        src,
                        sip_core::builder::respond_to(
                            &req,
                            488,
                            "Not Acceptable Here",
                            Vec::new(),
                            None,
                        ),
                    )
                    .await;
                    return;
                }
            }
        } else {
            let Ok(s) = UdpSocket::bind(("0.0.0.0", self.cfg.media_base_port)).await else {
                tracing::error!(%call_id, "media bind failed");
                return;
            };
            let s = Arc::new(s);
            let port = s.local_addr().map(|a| a.port()).unwrap_or(0);
            (Some(s), None, port)
        };
        let webrtc_caps = a_webrtc.as_ref().map(|w| {
            let t = w.answer_transport();
            sdp_util::WebrtcAnswerCaps {
                ufrag: t.ufrag,
                pwd: t.pwd,
                fingerprint: t.fingerprint,
                candidates: t.candidates,
            }
        });
        let answer = match sdp_util::answer(
            &offer,
            &self.cfg.media_host,
            a_port,
            &self.cfg.codecs,
            webrtc_caps,
        ) {
            Ok(ans) => ans,
            Err(e) => {
                tracing::info!(%call_id, "SDP negotiation failed: {e:?}");
                send_staged(
                    &mut a_tx,
                    sock,
                    src,
                    sip_core::builder::respond_to(
                        &req,
                        488,
                        "Not Acceptable Here",
                        Vec::new(),
                        None,
                    ),
                )
                .await;
                return;
            }
        };
        // The codec-bearing plan (the audio m-line) drives the pump; with
        // an application m-line first in the offer, plans[0] has no codec.
        let a_plan = stream_plans(&answer)
            .into_iter()
            .find(|p| p.codec.is_some());

        let from = req.headers.get("From").unwrap_or("").to_string();
        let to = req.headers.get("To").unwrap_or("").to_string();
        let from_tag = sip_core::uri::NameAddr::parse(&from)
            .ok()
            .and_then(|n| n.tag);
        let contact = req.headers.get("Contact").map(str::to_string);

        self.cdr
            .send(CdrEvent::LegInvited {
                call_id: call_id.clone(),
                side: Side::A,
                from,
                to,
                at: Instant::now(),
            })
            .ok();

        // Route lookup: longest matching prefix on the request-URI user.
        let user = req.uri.user.clone().unwrap_or_default();
        let target = self
            .cfg
            .routes
            .iter()
            .filter(|r| user.starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .map(|r| r.target.clone())
            .unwrap_or_else(|| self.cfg.default_target.clone());
        let target_uri = match SipUri::parse(&target) {
            Ok(u) => u,
            Err(_) => {
                tracing::error!(%call_id, "bad route target {target}");
                return;
            }
        };
        let Some(dst) = uri_to_socket(&target_uri).await else {
            tracing::error!(%call_id, "cannot resolve target {target}");
            return;
        };

        // Bind leg B media socket + build offer.
        let Ok(b_sock) = UdpSocket::bind(("0.0.0.0", self.cfg.media_base_port)).await else {
            tracing::error!(%call_id, "leg B media bind failed");
            return;
        };
        let b_sock = Arc::new(b_sock);
        let b_port = b_sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let offer_b = sdp_util::build_offer(
            &self.cfg.media_host,
            b_port,
            &self.cfg.codecs,
            rand::thread_rng().gen(),
        )
        .serialize();

        // UAC INVITE. Session timers on leg B: mirror the negotiated
        // interval and elect ourselves as refresher (`refresher=uac`) so
        // the B2BUA drives refreshes downstream too.
        let b_call_id = new_call_id("b2bua.local");
        let b_tag = new_tag();
        let branch = new_branch();
        let b_se = match negotiation {
            UasNegotiation::On { interval, .. } => {
                Some(interval.max(self.cfg.session_timer_min_se))
            }
            _ => None,
        };
        let mut invite = RequestBuilder::new(Method::Invite, target_uri.clone())
            .via(TransportKind::Udp, &local.to_string(), Some(&branch))
            .from(&format!("<sip:zrtc@{}>;tag={b_tag}", local_ip(local)))
            .to(&format!("<{target}>"))
            .call_id(Some(&b_call_id))
            .cseq(1)
            .contact(&format!("<sip:zrtc@{}>", local_ip(local)))
            .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, PRACK")
            .header("Supported", "100rel");
        if let Some(se) = b_se {
            invite = invite
                .header("Session-Expires", &format!("{se};refresher=uac"))
                .header("Supported", "100rel, timer");
        }
        let invite = invite
            .body("application/sdp", offer_b.clone().into_bytes())
            .build();

        // Leg B client INVITE transaction: the initial send goes through
        // TxEvent::Send, which also arms Timer A/B (RFC 3261 §17.1.1.2).
        let mut b_tx = ClientInviteTx::new(invite.clone(), TxTransport::Udp);
        for act in b_tx.on_event(TxEvent::Send, Instant::now()) {
            if let TxAction::SendRequest(r) = act {
                let _ = sock.send_to(&serialize(&SipMessage::Request(r)), dst).await;
            }
        }

        // 180 Ringing to A (through the server transaction). Reliable
        // (RFC 3262) when the caller supports 100rel: `Require: 100rel` +
        // `RSeq` on the response, retransmitted until the PRACK, and the
        // final response is parked until that PRACK arrives (§3).
        let mut a_rel: Option<AwaitPrack> = None;
        if caller_rel100 {
            // RSeq space: RFC 3262 §3 — initial value between 1 and 2³¹−1.
            let rseq = rand::thread_rng().gen_range(1..=i32::MAX as u32);
            let mut ringing =
                sip_core::builder::respond_to(&req, 180, "Ringing", Vec::new(), Some(&a_tag));
            ringing.headers.add("Require", "100rel");
            ringing.headers.add("RSeq", rseq.to_string());
            let bytes = serialize(&SipMessage::Response(ringing.clone()));
            send_staged(&mut a_tx, sock, src, ringing).await;
            a_rel = Some(AwaitPrack {
                state: Reliable1xx::new(rseq, Instant::now()),
                bytes,
            });
        } else {
            send_staged(
                &mut a_tx,
                sock,
                src,
                sip_core::builder::respond_to(&req, 180, "Ringing", Vec::new(), Some(&a_tag)),
            )
            .await;
        }

        let leg_a_timer = match negotiation {
            UasNegotiation::On { interval, role } => Some(LegTimers::new(interval, role)),
            _ => None,
        };
        // The UAS's own CSeq space starts above the received INVITE's CSeq.
        let a_next_cseq = req
            .headers
            .cseq()
            .map(|c| c.seq.saturating_add(1))
            .unwrap_or(1);
        let mut call = Call::new(answer.serialize(), offer_b);
        // The answer accepted the data channel iff the offer carried one and
        // the leg negotiated WebRTC (the SDP layer answers application
        // m-lines only on webrtc legs) — the establishment spawns the engine.
        call.a_dc_port = dc_offer.then_some(remote_sctp_port);
        call.a_rel = a_rel;
        let leg_a = Leg {
            call_id: call_id.clone(),
            local_tag: a_tag,
            remote_tag: from_tag,
            remote_sip: src,
            next_cseq: a_next_cseq,
            invite: Some(req),
            contact,
            plan: a_plan,
            rtp: a_sock,
            media: None,
            confirmed: false,
            timer: leg_a_timer,
            last_prack: None,
            webrtc: a_webrtc,
            dc: None,
        };
        call.leg_a = Some(leg_a);
        call.a_tx = Some(a_tx);
        call.b_tx = Some(b_tx);
        call.b_se = b_se;
        call.leg_b = Some(Leg {
            call_id: b_call_id.clone(),
            local_tag: b_tag,
            remote_tag: None,
            remote_sip: dst,
            next_cseq: 2,
            invite: None,
            contact: Some(format!("<{target}>")),
            plan: None,
            rtp: Some(b_sock),
            media: None,
            confirmed: false,
            timer: None,
            last_prack: None,
            webrtc: None,
            dc: None,
        });
        b_to_a.insert(b_call_id, call_id.clone());
        self.cdr
            .send(CdrEvent::LegInvited {
                call_id: call_id.clone(),
                side: Side::B,
                from: format!("<sip:zrtc@{}>", local_ip(local)),
                to: target,
                at: Instant::now(),
            })
            .ok();
        calls.insert(call_id, call);
    }

    /// Handles the leg-B 200 (dial). Internal but takes the full per-call
    /// context, like `on_invite`.
    #[allow(clippy::too_many_arguments)]
    async fn on_b_answered(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        a_id: &str,
        b_id: &str,
        resp: Response,
    ) {
        let Some(call) = calls.get_mut(a_id) else {
            return;
        };
        let Some(b) = call.leg_b.as_mut() else { return };
        b.remote_tag = resp
            .headers
            .get("To")
            .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
            .and_then(|n| n.tag);
        if let Some(c) = resp.headers.get("Contact") {
            b.contact = Some(c.to_string());
        }
        b.confirmed = true;
        // RFC 4028: adopt what the peer confirmed on leg B — interval from
        // the 200, role from its refresher parameter (default refresher is
        // the UAC, which is us on this leg).
        b.timer = resp.headers.session_expires().map(|se| {
            let role = match resp.headers.session_refresher() {
                Some(Refresher::Uas) => Role::Refreshee,
                _ => Role::Refresher,
            };
            LegTimers::new(se.max(self.cfg.session_timer_min_se), role)
        });
        match sdp::parse::parse(&String::from_utf8_lossy(&resp.body)) {
            Ok(answer_sdp) => {
                b.plan = stream_plans(&answer_sdp).into_iter().next();
            }
            Err(e) => {
                tracing::warn!(call_id = %a_id, "bad SDP from B: {e}");
                if let Some(a) = &call.leg_a {
                    if let Some(invite) = &a.invite {
                        let fail = sip_core::builder::respond_to(
                            invite,
                            503,
                            "Service Unavailable",
                            Vec::new(),
                            None,
                        );
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(fail)), a.remote_sip)
                            .await;
                    }
                }
                teardown(calls, b_to_a, a_id, "bad SDP from leg B", Some(503));
                return;
            }
        }
        if let Some(b) = call.leg_b.as_ref() {
            let cseq = resp.headers.cseq().map(|c| c.seq).unwrap_or(1);
            self.send_ack(sock, b, cseq);
        }

        self.cdr
            .send(CdrEvent::LegAnswered {
                call_id: a_id.to_string(),
                side: Side::B,
                codec: call.leg_b.as_ref().map(Leg::codec_name).unwrap_or_default(),
                at: Instant::now(),
            })
            .ok();
        // leg-up tap (side B answered)
        observ::session::emit_for(
            a_id,
            observ::EventKind::B2buaLegUp {
                side: "B".into(),
                peer: call
                    .leg_b
                    .as_ref()
                    .map(|l| l.remote_sip)
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                codec: call.leg_b.as_ref().map(Leg::codec_name).unwrap_or_default(),
            },
        );
        self.cdr
            .send(CdrEvent::LegConfirmed {
                call_id: a_id.to_string(),
                side: Side::B,
                at: Instant::now(),
            })
            .ok();

        // RFC 3262 §3: while our reliable 1xx is unacknowledged, no final
        // response may go out to leg A. Park the confirmation; the PRACK
        // handler flushes it.
        if call.a_rel.is_some() {
            tracing::debug!(call_id = %a_id, "parking 200 until PRACK (RFC 3262 §3)");
            call.a_hold = true;
            return;
        }
        self.confirm_leg_a(sock, local, calls, b_to_a, a_id).await;
        let _ = b_id;
    }

    /// Confirms leg A: the 200 (through the server INVITE transaction while
    /// it is open — afterwards the dialog-layer cached-200 path answers late
    /// INVITE retransmissions), the session-clock anchor (§10) and the media
    /// pump start. Split from `on_b_answered` because RFC 3262 §3 parks this
    /// until the caller's PRACK for our reliable 1xx has arrived.
    async fn confirm_leg_a(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        a_id: &str,
    ) {
        let (a_snapshot, response) = {
            let call = match calls.get_mut(a_id) {
                Some(c) => c,
                None => return,
            };
            let a = match call.leg_a.as_ref() {
                Some(a) => a,
                None => return,
            };
            let Some(invite) = &a.invite else { return };
            let mut response = sip_core::builder::respond_to(
                invite,
                200,
                "OK",
                call.a_answer.clone().into_bytes(),
                Some(&a.local_tag),
            );
            response
                .headers
                .add("Contact", format!("<sip:zrtc@{local}>"));
            response.headers.add("Supported", "timer, 100rel");
            if let Some(t) = a.timer.as_ref() {
                response.headers.add(
                    "Session-Expires",
                    format!(
                        "{};refresher={}",
                        t.interval,
                        timers::refresher_for(t.role, true)
                    ),
                );
            }
            let snapshot = (a.local_tag.clone(), a.remote_sip);
            (snapshot, response)
        };
        let call = match calls.get_mut(a_id) {
            Some(c) => c,
            None => return,
        };
        if let Some(mut a_tx) = call.a_tx.take() {
            send_staged(&mut a_tx, sock, a_snapshot.1, response).await;
        } else {
            let bytes = serialize(&SipMessage::Response(response));
            let _ = sock.send_to(&bytes, a_snapshot.1).await;
        }

        // The leg-A session clock starts at dialog establishment (§10), and
        // the ACK deadline arms here too (dialog-level Timer H).
        if let Some(a) = call.leg_a.as_mut() {
            if let Some(t) = a.timer.as_mut() {
                t.anchored = Instant::now();
            }
        }
        call.a_ack_deadline = Some(Instant::now() + ACK_TIMEOUT);

        // WebRTC leg establishment (RFC 5763 §5): the 200 OK carrying our
        // candidates is on the wire, so ICE checks can flow — connect, run
        // DTLS (we are the client, setup:active) and key the SRTP sessions.
        // The leg's pump starts only with established crypto: a negotiated
        // SAVPF leg must never send or accept plaintext media.  Failure
        // tears the call down (488/BYE) instead of degrading.
        let mut a_crypto: Option<media::CryptoPair> = None;
        let mut a_pair_remote: Option<SocketAddr> = None;
        let mut a_dtls_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>> = None;
        if let Some(a) = call.leg_a.as_mut() {
            if let Some(w) = a.webrtc.take() {
                match w.establish().await {
                    Ok(est) => {
                        tracing::info!(
                            call_id = %a_id,
                            peer = %est.remote,
                            "WebRTC leg up: ICE + DTLS({}) + SRTP",
                            est.crypto.tx.profile().dtls_name().unwrap_or("?")
                        );
                        a.rtp = Some(est.socket.clone());
                        a_pair_remote = Some(est.remote);
                        a_crypto = Some(est.crypto);
                        // Data channels ride the SAME DTLS association
                        // (RFC 8261): hand the endpoint to the engine and
                        // give the pump the DTLS-record forwarder.
                        if let Some(remote_sctp_port) = call.a_dc_port {
                            let (dtls_tx, dtls_rx) = tokio::sync::mpsc::unbounded_channel();
                            let dc = datachan::spawn(
                                datachan::DataChannelConfig {
                                    remote_sctp_port,
                                    ..datachan::DataChannelConfig::default()
                                },
                                est.dtls,
                                est.socket.clone(),
                                est.remote,
                                dtls_rx,
                            );
                            a.dc = Some(dc);
                            a_dtls_tx = Some(dtls_tx);
                        }
                        // Without a negotiated data channel the DTLS
                        // association has nothing left to carry — dropping
                        // it here is the documented lifecycle.
                    }
                    Err(e) => {
                        tracing::warn!(call_id = %a_id, "WebRTC establishment failed: {e}");
                        // No media path to leg A: release the call.  Leg B
                        // has not been confirmed into a bridged call yet
                        // (its pump never started), so a plain teardown with
                        // BYEs is safe here.
                        teardown(
                            calls,
                            b_to_a,
                            a_id,
                            "WebRTC establishment failed",
                            Some(488),
                        );
                        return;
                    }
                }
            }
        }

        // Start both media pumps.
        let sockets = (
            call.leg_a.as_ref().and_then(|l| l.rtp.clone()),
            call.leg_b.as_ref().and_then(|l| l.rtp.clone()),
        );
        if let (Some(a_sock), Some(b_sock)) = sockets {
            let pa = call.leg_a.as_ref().and_then(|l| l.plan.clone());
            let pb = call.leg_b.as_ref().and_then(|l| l.plan.clone());
            if let (Some(pa), Some(pb)) = (pa, pb) {
                let codec_a = pa
                    .codec
                    .as_ref()
                    .and_then(|(n, c, _)| sdp_util::codec_id_for(n, *c));
                let codec_b = pb
                    .codec
                    .as_ref()
                    .and_then(|(n, c, _)| sdp_util::codec_id_for(n, *c));
                match (codec_a, codec_b) {
                    (Some(ca), Some(cb)) => {
                        let cfg_a = PumpConfig {
                            rx_codec: ca,
                            tx_codec: ca,
                            rx_pt: pa.local_pt,
                            te_pt_rx: pa.telephone_event_pt,
                            te_pt_tx: pa.telephone_event_pt,
                            tx_pt: pa.local_pt,
                            // RTCP feedback channels negotiated on this leg
                            // (the remote's offer/answer rtcp-fb + extmap).
                            nack: pa.rtcp_fb_nack,
                            twcc_ext: pa.twcc_ext_id,
                            rtcp_interval_ms: 5_000,
                            // RFC 7983 DTLS records → the data-channel
                            // engine (None drops them, per the pump).
                            dtls_tx: a_dtls_tx.take(),
                        };
                        let cfg_b = PumpConfig {
                            rx_codec: cb,
                            tx_codec: cb,
                            rx_pt: pb.local_pt,
                            te_pt_rx: pb.telephone_event_pt,
                            te_pt_tx: pb.telephone_event_pt,
                            tx_pt: pb.local_pt,
                            nack: pb.rtcp_fb_nack,
                            twcc_ext: pb.twcc_ext_id,
                            rtcp_interval_ms: 5_000,
                            // Leg B is a plain RTP/AVP leg: no DTLS seam.
                            dtls_tx: None,
                        };
                        // Cross-connect the pumps: A's decoded bridge PCM feeds
                        // B's encoder and vice versa.
                        let (a_out, b_in) = tokio::sync::mpsc::channel(64);
                        let (b_out, a_in) = tokio::sync::mpsc::channel(64);
                        let sess_a = observ::CallSession::new(a_id, None, None)
                            .with_leg(observ::event::Leg::A);
                        let sess_b = observ::CallSession::new(a_id, None, None)
                            .with_leg(observ::event::Leg::B);
                        match (
                            media::start_with_socket_session_crypto(
                                cfg_a,
                                a_sock,
                                a_crypto.take(),
                                a_out,
                                a_in,
                                sess_a,
                            ),
                            media::start_with_socket_session(cfg_b, b_sock, b_out, b_in, sess_b),
                        ) {
                            (Ok(ha), Ok(hb)) => {
                                // A secured (WebRTC) leg routes media at the
                                // ICE-nominated pair, not the offer's c= line.
                                if let Some(pair) = a_pair_remote {
                                    *ha.remote.lock().await = Some(pair);
                                } else {
                                    seed_remote(&ha, &pa).await;
                                }
                                seed_remote(&hb, &pb).await;
                                if let Some(a) = call.leg_a.as_mut() {
                                    a.media = Some(ha);
                                }
                                if let Some(b) = call.leg_b.as_mut() {
                                    b.media = Some(hb);
                                }
                                tracing::info!(call_id = %a_id, "media bridge up: {:?} <-> {:?}", ca, cb);
                                self.cdr
                                    .send(CdrEvent::LegAnswered {
                                        call_id: a_id.to_string(),
                                        side: Side::A,
                                        codec: format!("{ca:?}"),
                                        at: Instant::now(),
                                    })
                                    .ok();
                                // leg-up tap (side A answered)
                                observ::session::emit_for(
                                    a_id,
                                    observ::EventKind::B2buaLegUp {
                                        side: "A".into(),
                                        peer: call
                                            .leg_a
                                            .as_ref()
                                            .map(|l| l.remote_sip)
                                            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
                                        codec: format!("{ca:?}"),
                                    },
                                );
                            }
                            (Err(e), _) | (_, Err(e)) => {
                                tracing::error!(call_id = %a_id, "pump start failed: {e}");
                            }
                        }
                    }
                    _ => tracing::warn!(call_id = %a_id, "unsupported codec pair"),
                }
            }
        }
    }

    fn on_ack(&self, calls: &mut HashMap<String, Call>, ack: &Request, call_id: &str) {
        if let Some(c) = calls.get_mut(call_id) {
            // Feed the ACK to the leg-A server transaction (§17.2.3): it
            // confirms the transaction and arms Timer I. After a 2xx the
            // transaction is already gone and this is a no-op.
            if let Some(tx) = c.a_tx.as_mut() {
                let _ = tx.on_event(TxEvent::ReceivedRequest(ack.clone()), Instant::now());
                if tx.state() == TxState::Terminated {
                    c.a_tx = None;
                }
            }
            if let Some(a) = c.leg_a.as_mut() {
                if !a.confirmed {
                    a.confirmed = true;
                    c.a_ack_deadline = None;
                    self.cdr
                        .send(CdrEvent::LegConfirmed {
                            call_id: call_id.to_string(),
                            side: Side::A,
                            at: Instant::now(),
                        })
                        .ok();
                }
            }
        }
    }

    async fn on_bye(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: &Request,
        call_id: String,
        src: SocketAddr,
    ) {
        let resp = sip_core::builder::respond_to(req, 200, "OK", Vec::new(), None);
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(resp)), src)
            .await;

        let a_id = b_to_a
            .get(&call_id)
            .cloned()
            .unwrap_or_else(|| call_id.clone());
        let from_b = call_id != a_id;

        // Relay BYE to the other leg.
        if let Some(c) = calls.get_mut(&a_id) {
            let other = if from_b {
                c.leg_a.as_mut()
            } else {
                c.leg_b.as_mut()
            };
            if let Some(o) = other {
                Self::send_bye(sock, o).await;
            }
            let sender_side = if from_b { Side::B } else { Side::A };
            let other_side = if from_b { Side::A } else { Side::B };
            self.cdr
                .send(CdrEvent::LegTerminated {
                    call_id: a_id.clone(),
                    side: sender_side,
                    reason: "BYE received".into(),
                    at: Instant::now(),
                })
                .ok();
            self.cdr
                .send(CdrEvent::LegTerminated {
                    call_id: a_id.clone(),
                    side: other_side,
                    reason: "BYE relayed".into(),
                    at: Instant::now(),
                })
                .ok();
        }
        teardown(calls, b_to_a, &a_id, "BYE", None);
    }

    async fn on_cancel(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: &Request,
        call_id: String,
        src: SocketAddr,
    ) {
        let Some(c) = calls.get_mut(&call_id) else {
            // §9.2: a CANCEL for a transaction we cannot find gets 481.
            let resp = sip_core::builder::respond_to(
                req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        };
        // RFC 3261 §9.2: a CANCEL has no effect on an INVITE whose final
        // response is already out — an answered call must survive it, and
        // the CANCEL belongs to no open transaction (481).
        if c.leg_a.as_ref().map(|a| a.confirmed).unwrap_or(false) {
            let resp = sip_core::builder::respond_to(
                req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        // The INVITE transaction is still unanswered: 200 to the CANCEL
        // itself, then 487 to A through the server transaction when it is
        // still open.
        let resp = sip_core::builder::respond_to(req, 200, "OK", Vec::new(), None);
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(resp)), src)
            .await;
        if let Some(a) = &c.leg_a {
            if let Some(invite) = &a.invite {
                let resp487 = sip_core::builder::respond_to(
                    invite,
                    487,
                    "Request Terminated",
                    Vec::new(),
                    Some(&a.local_tag),
                );
                if let Some(mut a_tx) = c.a_tx.take() {
                    send_staged(&mut a_tx, sock, a.remote_sip, resp487).await;
                } else {
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp487)), a.remote_sip)
                        .await;
                }
            }
        }
        // §9.1: CANCEL the outgoing dial INVITE while leg B is still
        // ringing; a leg B that already answered (its 200 is parked on the
        // PRACK, RFC 3262 §3) is confirmed and gets a BYE instead.
        if c.leg_b.as_ref().map(|b| b.confirmed).unwrap_or(false) {
            if let Some(b) = c.leg_b.as_mut() {
                Self::send_bye(sock, b).await;
            }
        } else if let Some(b_tx) = c.b_tx.as_ref() {
            if let Some(b) = c.leg_b.as_ref() {
                let cancel = build_cancel(b_tx.request());
                let _ = sock
                    .send_to(&serialize(&SipMessage::Request(cancel)), b.remote_sip)
                    .await;
            }
        }
        teardown(calls, b_to_a, &call_id, "CANCEL", None);
    }

    fn send_ack(&self, sock: &Arc<UdpSocket>, b: &Leg, cseq: u32) {
        let req_uri = b
            .contact
            .clone()
            .and_then(|c| extract_uri(&c))
            .unwrap_or_else(|| SipUri::parse(&format!("sip:peer@{}", b.remote_sip)).unwrap());
        let ack = RequestBuilder::new(Method::Ack, req_uri)
            .via(TransportKind::Udp, &via_sent_by(), Some(&new_branch()))
            .from(&format!("<sip:zrtc@b2bua>;tag={}", b.local_tag))
            .to(&format!(
                "<sip:peer>;tag={}",
                b.remote_tag.clone().unwrap_or_default()
            ))
            .call_id(Some(&b.call_id))
            .cseq(cseq)
            .build();
        let bytes = serialize(&SipMessage::Request(ack));
        let sock = sock.clone();
        let dst = b.remote_sip;
        tokio::spawn(async move {
            let _ = sock.send_to(&bytes, dst).await;
        });
    }

    /// Sends an in-dialog BYE on a leg (consumes one CSeq).
    async fn send_bye(sock: &Arc<UdpSocket>, leg: &mut Leg) {
        let req_uri = leg
            .contact
            .clone()
            .and_then(|c| extract_uri(&c))
            .unwrap_or_else(|| SipUri::parse(&format!("sip:peer@{}", leg.remote_sip)).unwrap());
        let cseq = take_cseq(leg);
        let bye = RequestBuilder::new(Method::Bye, req_uri)
            .via(TransportKind::Udp, &via_sent_by(), Some(&new_branch()))
            .from(&format!("<sip:zrtc@b2bua>;tag={}", leg.local_tag))
            .to(&format!(
                "<sip:peer>;tag={}",
                leg.remote_tag.clone().unwrap_or_default()
            ))
            .call_id(Some(&leg.call_id))
            .cseq(cseq)
            .build();
        let bytes = serialize(&SipMessage::Request(bye));
        let _ = sock.send_to(&bytes, leg.remote_sip).await;
    }

    /// A 2xx to our leg-B session-refresh re-INVITE: re-anchor the clock.
    fn on_b_refreshed(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        a_id: &str,
        resp: &Response,
    ) {
        if let Some(call) = calls.get_mut(a_id) {
            if let Some(b) = call.leg_b.as_mut() {
                if let Some(t) = b.timer.as_mut() {
                    t.anchored = Instant::now();
                    t.pending = None;
                    tracing::debug!(
                        call_id = %a_id,
                        code = resp.code,
                        "leg B session refreshed (interval {}s)",
                        t.interval
                    );
                }
                // RFC 3261 §13.2.2.4: a 2xx to our own re-INVITE is ACKed at
                // dialog level (the client transaction only ACKs non-2xx).
                if let Some(cseq) = resp.headers.cseq().map(|c| c.seq) {
                    let ack_cseq = cseq;
                    if let Some(b) = call.leg_b.as_ref() {
                        self.send_ack(sock, b, ack_cseq);
                    }
                }
            }
        }
    }

    /// Handles responses that carry a leg-A Call-ID: the only requests we
    /// originate there are session-refresh re-INVITEs (and BYEs). Drives the
    /// pending leg-A client transaction, if any.
    async fn on_a_refresh_response(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        call_id: &str,
        resp: Response,
    ) {
        // Phase 1: drive the pending leg-A transaction (if any) and collect
        // what it wants done. The borrow of `calls` ends here so phase 2 can
        // act on the call map again.
        let drive = {
            let Some(call) = calls.get_mut(call_id) else {
                return;
            };
            let Some(a) = call.leg_a.as_ref() else {
                return;
            };
            // Only responses to our own leg-A refresh: they carry OUR local
            // tag in From (To mirrors the peer's tag).
            if resp.headers.from().and_then(|f| f.tag).as_deref() != Some(a.local_tag.as_str()) {
                return;
            }
            if resp.headers.cseq().map(|c| c.method) != Some(Method::Invite) {
                return; // e.g. 200 to our BYE — nothing to do
            }
            let dst = a.remote_sip;
            let Some(tx) = call.a_out_tx.as_mut() else {
                return;
            };
            let mut passed: Vec<Response> = Vec::new();
            let mut ack: Option<Vec<u8>> = None;
            for act in tx.on_event(TxEvent::Received(resp.clone()), Instant::now()) {
                match act {
                    TxAction::PassToTu(SipMessage::Response(r)) => passed.push(r),
                    TxAction::SendRequest(r) => ack = Some(serialize(&SipMessage::Request(r))),
                    _ => {}
                }
            }
            let terminated = tx.state() == TxState::Terminated;
            (passed, ack, dst, terminated)
        };
        let (passed, ack, dst, terminated) = drive;
        if terminated {
            if let Some(call) = calls.get_mut(call_id) {
                call.a_out_tx = None;
            }
        }
        if let Some(bytes) = ack {
            let _ = sock.send_to(&bytes, dst).await;
        }
        for r in passed {
            let class = r.code / 100;
            if class == 1 {
                continue;
            }
            if class == 2 {
                if let Some(a) = calls.get_mut(call_id).and_then(|c| c.leg_a.as_mut()) {
                    if let Some(t) = a.timer.as_mut() {
                        t.anchored = Instant::now();
                        t.pending = None;
                        tracing::debug!(
                            call_id = %call_id,
                            "leg A session refreshed (interval {}s)",
                            t.interval
                        );
                    }
                    // §13.2.2.4: ACK the 2xx at dialog level — without it the
                    // peer retransmits the 200 for the rest of the session.
                    if let Some(cseq) = r.headers.cseq().map(|c| c.seq) {
                        self.send_ack(sock, a, cseq);
                    }
                }
            } else {
                // Refresh refused: session over (RFC 4028 §11).
                tracing::info!(
                    call_id = %call_id,
                    "leg A session refresh rejected with {}",
                    r.code
                );
                if let Some(b) = calls.get_mut(call_id).and_then(|c| c.leg_b.as_mut()) {
                    Self::send_bye(sock, b).await;
                }
                teardown(calls, b_to_a, call_id, "leg A session refresh failed", None);
            }
        }
    }

    /// In-dialog re-INVITE on leg A: refresh (no change) → 200 with the
    /// cached answer; glare (initial transaction unfinished) → 491; SDP
    /// change → 488 (renegotiation unsupported).
    async fn on_a_reinvite(
        &self,
        sock: &Arc<UdpSocket>,
        call: &mut Call,
        req: &Request,
        src: SocketAddr,
        local: SocketAddr,
    ) {
        let Some(a) = call.leg_a.as_mut() else {
            return;
        };
        if req.headers.to().and_then(|t| t.tag).as_deref() != Some(a.local_tag.as_str()) {
            let resp = sip_core::builder::respond_to(
                req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        if call.a_tx.is_some() {
            // Initial INVITE still unfinished: glare (RFC 3261 §14.2).
            let resp = sip_core::builder::respond_to(req, 491, "Request Pending", Vec::new(), None);
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        let original_offer = a
            .invite
            .as_ref()
            .map(|i| i.body.clone())
            .unwrap_or_default();
        if !req.body.is_empty() && req.body != original_offer {
            tracing::info!(call_id = %a.call_id, "re-INVITE SDP change unsupported");
            let resp =
                sip_core::builder::respond_to(req, 488, "Not Acceptable Here", Vec::new(), None);
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        // Successful refresh: re-anchor the RFC 4028 clock on this leg.
        if let Some(t) = a.timer.as_mut() {
            t.anchored = Instant::now();
            t.pending = None;
        }
        let mut response = sip_core::builder::respond_to(
            req,
            200,
            "OK",
            call.a_answer.clone().into_bytes(),
            Some(&a.local_tag),
        );
        response
            .headers
            .add("Contact", format!("<sip:zrtc@{local}>"));
        response.headers.add("Supported", "timer");
        if let Some(t) = a.timer.as_ref() {
            response.headers.add(
                "Session-Expires",
                format!(
                    "{};refresher={}",
                    t.interval,
                    timers::refresher_for(t.role, true)
                ),
            );
        }
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(response)), src)
            .await;
    }

    /// In-dialog re-INVITE on leg B (the peer refreshing its downstream
    /// dialog, or glare while the dial is still in flight). Internal but
    /// takes the full per-call context, like `on_invite`.
    #[allow(clippy::too_many_arguments)]
    async fn on_b_reinvite(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: Request,
        call_id: &str,
        src: SocketAddr,
    ) {
        let Some(a_id) = b_to_a.get(call_id).cloned() else {
            return;
        };
        let Some(call) = calls.get_mut(&a_id) else {
            return;
        };
        let Some(b) = call.leg_b.as_mut() else {
            return;
        };
        // In-dialog requests from the peer carry OUR local tag in To.
        if req.headers.to().and_then(|t| t.tag).as_deref() != Some(b.local_tag.as_str()) {
            let resp = sip_core::builder::respond_to(
                &req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        if !b.confirmed {
            // The dial has not completed: glare.
            let resp =
                sip_core::builder::respond_to(&req, 491, "Request Pending", Vec::new(), None);
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        // Answer body: an empty request is a pure refresh (resend our
        // original offer as the new offer); an offer is answered only when
        // it does not change the negotiated media; anything else → 488.
        let answer_body: Vec<u8> = if req.body.is_empty() {
            call.b_offer.clone().into_bytes()
        } else {
            let offer = match sdp::parse::parse(&String::from_utf8_lossy(&req.body)) {
                Ok(o) => o,
                Err(_) => {
                    let resp =
                        sip_core::builder::respond_to(&req, 400, "Bad Request", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp)), src)
                        .await;
                    return;
                }
            };
            let port = b
                .rtp
                .as_ref()
                .and_then(|s| s.local_addr().ok())
                .map(|a| a.port())
                .unwrap_or(0);
            match sdp_util::answer(&offer, &self.cfg.media_host, port, &self.cfg.codecs, None) {
                Ok(ans) => {
                    // Renegotiation is only accepted when the media does not
                    // change — the pumps are already running with the current
                    // codec and payload type.
                    let new_plan = stream_plans(&ans).into_iter().next();
                    let same = match (&b.plan, &new_plan) {
                        (Some(cur), Some(np)) => {
                            cur.codec == np.codec && cur.local_pt == np.local_pt
                        }
                        _ => false,
                    };
                    if !same {
                        tracing::info!(
                            call_id = %a_id,
                            "leg B re-INVITE renegotiation unsupported"
                        );
                        let resp = sip_core::builder::respond_to(
                            &req,
                            488,
                            "Not Acceptable Here",
                            Vec::new(),
                            None,
                        );
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(resp)), src)
                            .await;
                        return;
                    }
                    ans.serialize().into_bytes()
                }
                Err(_) => {
                    let resp = sip_core::builder::respond_to(
                        &req,
                        488,
                        "Not Acceptable Here",
                        Vec::new(),
                        None,
                    );
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp)), src)
                        .await;
                    return;
                }
            }
        };
        // Successful refresh: re-anchor the clock.
        if let Some(t) = b.timer.as_mut() {
            t.anchored = Instant::now();
            t.pending = None;
        }
        let mut response =
            sip_core::builder::respond_to(&req, 200, "OK", answer_body, Some(&b.local_tag));
        response
            .headers
            .add("Contact", format!("<sip:zrtc@{local}>"));
        response.headers.add("Supported", "timer");
        if let Some(t) = b.timer.as_ref() {
            response.headers.add(
                "Session-Expires",
                format!(
                    "{};refresher={}",
                    t.interval,
                    timers::refresher_for(t.role, false)
                ),
            );
        }
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(response)), src)
            .await;
    }

    /// RFC 3262 §4 (UAS side): the caller's PRACK for our reliable 1xx.
    /// Answers `200` on a matching `RAck` (idempotent for retransmitted
    /// PRACKs whose first 200 was lost), `481` when nothing matches, `400`
    /// without a parseable `RAck`, and `488` when the PRACK carries an offer
    /// (renegotiation unsupported, like re-INVITEs).
    #[allow(clippy::too_many_arguments)]
    async fn on_prack(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: &Request,
        call_id: &str,
        src: SocketAddr,
    ) {
        let respond = |code: u16, reason: &str, tag: Option<&str>| {
            serialize(&SipMessage::Response(sip_core::builder::respond_to(
                req,
                code,
                reason,
                Vec::new(),
                tag,
            )))
        };
        // PRACK travels UAC → UAS; we are the UAC on leg-B dialogs, so a
        // PRACK there is invalid.
        if b_to_a.contains_key(call_id) {
            let _ = sock
                .send_to(&respond(481, "Call/Transaction Does Not Exist", None), src)
                .await;
            return;
        }
        let Some(call) = calls.get_mut(call_id) else {
            let _ = sock
                .send_to(&respond(481, "Call/Transaction Does Not Exist", None), src)
                .await;
            return;
        };
        let Some(a_tag) = call.leg_a.as_ref().map(|a| a.local_tag.clone()) else {
            return;
        };
        // In-dialog requests carry OUR local tag in To (§12.2.2).
        if req.headers.to().and_then(|t| t.tag).as_deref() != Some(a_tag.as_str()) {
            let _ = sock
                .send_to(
                    &respond(481, "Call/Transaction Does Not Exist", Some(&a_tag)),
                    src,
                )
                .await;
            return;
        }
        let Some(rack) = req.headers.rack_value() else {
            let _ = sock
                .send_to(&respond(400, "Bad Request", Some(&a_tag)), src)
                .await;
            return;
        };
        if !req.body.is_empty() {
            let _ = sock
                .send_to(&respond(488, "Not Acceptable Here", Some(&a_tag)), src)
                .await;
            return;
        }
        let invite_cseq = call
            .leg_a
            .as_ref()
            .and_then(|a| a.invite.as_ref())
            .and_then(|i| i.headers.cseq())
            .map(|c| c.seq)
            .unwrap_or(0);
        let outstanding = call.a_rel.as_ref().map(|r| r.state.rseq);
        let acknowledged = match outstanding {
            Some(rseq) => {
                if rel100::rack_matches(&rack, rseq, invite_cseq) {
                    // Acknowledged: stop retransmitting the reliable 1xx.
                    call.a_rel = None;
                    call.a_prack_acked = Some(rseq);
                    true
                } else {
                    let _ = sock
                        .send_to(
                            &respond(481, "Call/Transaction Does Not Exist", Some(&a_tag)),
                            src,
                        )
                        .await;
                    return;
                }
            }
            None => {
                // Retransmitted PRACK after we already acknowledged it: the
                // first 200 was probably lost — re-answer idempotently.
                if call.a_prack_acked == Some(rack.rseq)
                    && rack.cseq == invite_cseq
                    && rack.method == Method::Invite
                {
                    let _ = sock.send_to(&respond(200, "OK", Some(&a_tag)), src).await;
                    return;
                }
                let _ = sock
                    .send_to(
                        &respond(481, "Call/Transaction Does Not Exist", Some(&a_tag)),
                        src,
                    )
                    .await;
                return;
            }
        };
        let _ = sock.send_to(&respond(200, "OK", Some(&a_tag)), src).await;
        if acknowledged {
            tracing::debug!(call_id = %call_id, "reliable 1xx acknowledged (RAck {rack})");
        }
        // RFC 3262 §3: the parked 200 can go out now.
        let confirm_now = call.a_hold;
        if confirm_now {
            call.a_hold = false;
        }
        if confirm_now {
            self.confirm_leg_a(sock, local, calls, b_to_a, call_id)
                .await;
        }
    }

    /// RFC 3262 §4 (UAC side): a reliable 1xx on the leg-B dial is answered
    /// with PRACK carrying `RAck` — but only for a 101–199 that carries BOTH
    /// `Require: 100rel` and an `RSeq`. The peer retransmitting the 1xx
    /// (same RSeq) means our PRACK was lost — the STORED PRACK is resent
    /// verbatim (same CSeq number and same branch, RFC 3261 §17.1.2).
    async fn prack_leg_b_1xx(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        a_id: &str,
        r1xx: &Response,
    ) {
        let Some(call) = calls.get_mut(a_id) else {
            return;
        };
        let Some(b) = call.leg_b.as_mut() else {
            return;
        };
        let action = rel100::prack_action(
            r1xx.code,
            r1xx.headers.require().has("100rel"),
            r1xx.headers.rseq(),
            b.last_prack.as_ref().map(|p| p.rseq),
        );
        match action {
            rel100::PrackAction::Ignore => {}
            rel100::PrackAction::Retransmit => {
                // Resend the stored PRACK byte-identical: same CSeq, same
                // branch (RFC 3261 §17.1.2) — the peer matches it by branch.
                let Some(stored) = b.last_prack.as_ref() else {
                    return;
                };
                tracing::debug!(
                    call_id = %a_id,
                    "retransmitted 1xx (RSeq {}): resending stored PRACK",
                    stored.rseq
                );
                let _ = sock.send_to(&stored.bytes, b.remote_sip).await;
            }
            rel100::PrackAction::Send { rseq } => {
                // Early dialog: the 1xx's To tag is the peer's dialog tag.
                if b.remote_tag.is_none() {
                    b.remote_tag = r1xx.headers.to().and_then(|t| t.tag);
                }
                let invite_cseq = r1xx.headers.cseq().map(|c| c.seq).unwrap_or(1);
                let req_uri = b
                    .contact
                    .clone()
                    .and_then(|c| extract_uri(&c))
                    .unwrap_or_else(|| {
                        SipUri::parse(&format!("sip:peer@{}", b.remote_sip)).unwrap()
                    });
                let cseq = take_cseq(b);
                let prack = RequestBuilder::new(Method::Prack, req_uri)
                    .via(TransportKind::Udp, &via_sent_by(), Some(&new_branch()))
                    .from(&format!("<sip:zrtc@b2bua>;tag={}", b.local_tag))
                    .to(&format!(
                        "<sip:peer>;tag={}",
                        b.remote_tag.clone().unwrap_or_default()
                    ))
                    .call_id(Some(&b.call_id))
                    .cseq(cseq)
                    .header("RAck", &format!("{rseq} {invite_cseq} INVITE"))
                    .build();
                let bytes = serialize(&SipMessage::Request(prack));
                b.last_prack = Some(SentPrack {
                    rseq,
                    bytes: bytes.clone(),
                });
                let _ = sock.send_to(&bytes, b.remote_sip).await;
                tracing::debug!(call_id = %a_id, "PRACK sent for RSeq {rseq}");
            }
        }
    }

    /// 421 Extension Required from leg B on the dial: the peer insists on
    /// `100rel` (RFC 3262 §3 — a UAS requiring it answers 421 carrying
    /// `Require`). Retries once, merging the 421's `Require` tokens into the
    /// retry's `Supported` header. Returns false when the retry was already
    /// spent or is impossible.
    async fn retry_b_421(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        a_id: &str,
        b_call_id: &str,
        resp: &Response,
    ) -> bool {
        let Some(call) = calls.get_mut(a_id) else {
            return false;
        };
        if call.b_421_retried {
            tracing::info!(call_id = %a_id, "leg B 421 retry already spent");
            return false;
        }
        call.b_421_retried = true;
        let Some(b) = call.leg_b.as_ref() else {
            return false;
        };
        let Some(target) = b.contact.clone().and_then(|c| extract_uri(&c)) else {
            tracing::error!(call_id = %a_id, "421 retry: no leg B target");
            return false;
        };
        let Some(dst) = uri_to_socket(&target).await else {
            tracing::error!(call_id = %a_id, "421 retry: cannot resolve {target}");
            return false;
        };
        let to_text = format!("<{target}>");
        let (b_local_tag, offer, b_se) = (b.local_tag.clone(), call.b_offer.clone(), call.b_se);
        let cseq = take_cseq(call.leg_b.as_mut().unwrap());
        // Merge what the 421 demanded into our Supported (keep "100rel" and
        // "timer" — the peer may demand more than it announced so far).
        let base = if b_se.is_some() {
            "100rel, timer"
        } else {
            "100rel"
        };
        let supported = rel100::merge_supported(base, &resp.headers.require().to_string());
        tracing::info!(
            call_id = %a_id,
            "leg B 421: retrying with Supported: {supported}"
        );
        let mut builder = RequestBuilder::new(Method::Invite, target)
            .via(TransportKind::Udp, &local.to_string(), Some(&new_branch()))
            .from(&format!(
                "<sip:zrtc@{}>;tag={}",
                local_ip(local),
                b_local_tag
            ))
            .to(&to_text)
            .call_id(Some(b_call_id))
            .cseq(cseq)
            .contact(&format!("<sip:zrtc@{}>", local_ip(local)))
            .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, PRACK")
            .header("Supported", &supported);
        if let Some(se) = b_se {
            builder = builder.header("Session-Expires", &format!("{se};refresher=uac"));
        }
        let invite = builder.body("application/sdp", offer.into_bytes()).build();
        let mut tx = ClientInviteTx::new(invite, TxTransport::Udp);
        for act in tx.on_event(TxEvent::Send, Instant::now()) {
            if let TxAction::SendRequest(r) = act {
                let _ = sock.send_to(&serialize(&SipMessage::Request(r)), dst).await;
            }
        }
        let call = calls.get_mut(a_id).unwrap();
        call.b_tx = Some(tx);
        call.b_tx_kind = BInviteKind::Dial;
        true
    }

    /// UPDATE (RFC 3311): accepted as a session refresh when it carries no
    /// offer; offers are refused with 488 (renegotiation unsupported).
    async fn on_update(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        b_to_a: &mut HashMap<String, String>,
        req: &Request,
        call_id: &str,
        src: SocketAddr,
    ) {
        let a_id = b_to_a
            .get(call_id)
            .cloned()
            .unwrap_or_else(|| call_id.to_string());
        let Some(call) = calls.get_mut(&a_id) else {
            let resp = sip_core::builder::respond_to(
                req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        };
        let we_are_uas = a_id == call_id;
        let Some(leg) = (if we_are_uas {
            call.leg_a.as_mut()
        } else {
            call.leg_b.as_mut()
        }) else {
            return;
        };
        // In-dialog requests from the peer carry OUR local tag in To.
        if req.headers.to().and_then(|t| t.tag).as_deref() != Some(leg.local_tag.as_str()) {
            let resp = sip_core::builder::respond_to(
                req,
                481,
                "Call/Transaction Does Not Exist",
                Vec::new(),
                None,
            );
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        if !leg.confirmed {
            let resp = sip_core::builder::respond_to(req, 491, "Request Pending", Vec::new(), None);
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        if !req.body.is_empty() {
            let resp =
                sip_core::builder::respond_to(req, 488, "Not Acceptable Here", Vec::new(), None);
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(resp)), src)
                .await;
            return;
        }
        // A successful UPDATE refreshes the session (RFC 4028 §7.3).
        if let Some(t) = leg.timer.as_mut() {
            t.anchored = Instant::now();
            t.pending = None;
        }
        let resp = sip_core::builder::respond_to(req, 200, "OK", Vec::new(), None);
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(resp)), src)
            .await;
    }

    /// 422 from leg B on the initial dial: retry with the peer's `Min-SE`
    /// (RFC 4028 §7). Returns false when no usable retry is possible.
    async fn retry_b_422(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
        a_id: &str,
        b_call_id: &str,
        resp: &Response,
    ) -> bool {
        let Some(call) = calls.get_mut(a_id) else {
            return false;
        };
        let Some(b) = call.leg_b.as_ref() else {
            return false;
        };
        let peer_min = resp
            .headers
            .min_se()
            .unwrap_or(self.cfg.session_timer_min_se);
        let prev = call.b_se.unwrap_or(0);
        let new_se = peer_min.max(prev);
        if new_se <= prev {
            tracing::info!(call_id = %a_id, "leg B 422 without a Min-SE increase");
            return false;
        }
        let Some(target) = b.contact.clone().and_then(|c| extract_uri(&c)) else {
            tracing::error!(call_id = %a_id, "422 retry: no leg B target");
            return false;
        };
        let Some(dst) = uri_to_socket(&target).await else {
            tracing::error!(call_id = %a_id, "422 retry: cannot resolve {target}");
            return false;
        };
        let to_text = format!("<{target}>");
        let (b_local_tag, offer) = (b.local_tag.clone(), call.b_offer.clone());
        let cseq = take_cseq(call.leg_b.as_mut().unwrap());
        tracing::info!(
            call_id = %a_id,
            "leg B 422: retrying with Session-Expires {new_se}"
        );
        let invite = RequestBuilder::new(Method::Invite, target)
            .via(TransportKind::Udp, &local.to_string(), Some(&new_branch()))
            .from(&format!(
                "<sip:zrtc@{}>;tag={}",
                local_ip(local),
                b_local_tag
            ))
            .to(&to_text)
            .call_id(Some(b_call_id))
            .cseq(cseq)
            .contact(&format!("<sip:zrtc@{}>", local_ip(local)))
            .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, PRACK")
            .header("Session-Expires", &format!("{new_se};refresher=uac"))
            .header("Supported", "timer, 100rel")
            .body("application/sdp", offer.into_bytes())
            .build();
        let mut tx = ClientInviteTx::new(invite, TxTransport::Udp);
        for act in tx.on_event(TxEvent::Send, Instant::now()) {
            if let TxAction::SendRequest(r) = act {
                let _ = sock.send_to(&serialize(&SipMessage::Request(r)), dst).await;
            }
        }
        let call = calls.get_mut(a_id).unwrap();
        call.b_tx = Some(tx);
        call.b_tx_kind = BInviteKind::Dial;
        call.b_se = Some(new_se);
        true
    }
}

// ---- helpers ---------------------------------------------------------------

/// Consumes the next CSeq for requests we originate on a leg.
fn take_cseq(leg: &mut Leg) -> u32 {
    let c = leg.next_cseq;
    leg.next_cseq = c.saturating_add(1);
    c
}

/// Builds the CANCEL for an outstanding INVITE (RFC 3261 §9.1): same
/// Request-URI, the INVITE's top Via verbatim (so sent-by and branch match
/// the INVITE transaction), the INVITE's CSeq number with method CANCEL,
/// mirrored From/To/Call-ID and the INVITE's Route set.
fn build_cancel(invite: &Request) -> Request {
    let mut cancel = RequestBuilder::new(Method::Cancel, invite.uri.clone())
        .from(invite.headers.get("From").unwrap_or("<sip:zrtc@b2bua>"))
        .to(invite.headers.get("To").unwrap_or("<sip:peer>"))
        .call_id(invite.headers.call_id())
        .cseq(invite.headers.cseq().map(|c| c.seq).unwrap_or(1))
        .build();
    cancel.headers.remove_all("Via");
    if let Some(via) = invite.headers.get("Via") {
        cancel.headers.add("Via", via);
    }
    let routes = invite.headers.get_all("Route");
    if !routes.is_empty() {
        cancel.headers.remove_all("Route");
        for r in routes {
            cancel.headers.add("Route", r);
        }
    }
    cancel
}

/// What a leg's RFC 4028 clock wants done right now.
enum TimerAction {
    /// We are the refresher and half the interval has elapsed (§9).
    Refresh,
    /// The leg let the clock run out (§10).
    Expired,
}

/// Reads a leg's timer clock. Unconfirmed legs are inert — their dialog has
/// not been established, so the session interval has not started.
fn leg_timer_action(leg: &Leg, now: Instant) -> Option<TimerAction> {
    let t = leg.timer.as_ref()?;
    if !leg.confirmed {
        return None;
    }
    if t.refresh_due(now) {
        Some(TimerAction::Refresh)
    } else if t.expired(now) {
        Some(TimerAction::Expired)
    } else {
        None
    }
}

/// Builds a no-change session-refresh re-INVITE (RFC 4028 §7.2) for a leg.
/// The body, when present, is the leg's original offer byte-for-byte.
fn refresh_reinvite(leg: &Leg, cseq: u32, we_are_uas: bool, offer: Vec<u8>) -> Request {
    let req_uri = leg
        .contact
        .clone()
        .and_then(|c| extract_uri(&c))
        .unwrap_or_else(|| SipUri::parse(&format!("sip:peer@{}", leg.remote_sip)).unwrap());
    let mut invite = RequestBuilder::new(Method::Invite, req_uri)
        .via(TransportKind::Udp, &via_sent_by(), Some(&new_branch()))
        .from(&format!("<sip:zrtc@b2bua>;tag={}", leg.local_tag))
        .to(&format!(
            "<sip:peer>;tag={}",
            leg.remote_tag.clone().unwrap_or_default()
        ))
        .call_id(Some(&leg.call_id))
        .cseq(cseq)
        .contact("<sip:zrtc@b2bua>")
        .header("Supported", "timer, 100rel")
        .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, PRACK");
    if let Some(t) = leg.timer.as_ref() {
        invite = invite.header(
            "Session-Expires",
            &format!(
                "{};refresher={}",
                t.interval,
                timers::refresher_for(t.role, we_are_uas)
            ),
        );
    }
    if !offer.is_empty() {
        invite = invite.body("application/sdp", offer);
    }
    invite.build()
}

/// Stages `resp` on a server transaction and transmits whatever the state
/// machine emits (SendResponse actions only; timers are the caller's job).
async fn send_staged(
    tx: &mut ServerInviteTx,
    sock: &Arc<UdpSocket>,
    dst: SocketAddr,
    resp: Response,
) {
    tx.stage(resp);
    for act in tx.on_event(TxEvent::Send, Instant::now()) {
        if let TxAction::SendResponse(r) = act {
            let _ = sock
                .send_to(&serialize(&SipMessage::Response(r)), dst)
                .await;
        }
    }
}

/// Seeds the pump's remote media address from the negotiated SDP plan
/// (latching still overrides on the first inbound packet).
async fn seed_remote(handle: &PumpHandle, plan: &StreamPlan) {
    if plan.remote_port != 0 {
        if let Some(ip) = plan.remote_addr {
            *handle.remote.lock().await = Some(SocketAddr::new(ip, plan.remote_port));
        }
    }
}

fn local_ip(local: SocketAddr) -> std::net::IpAddr {
    if local.ip().is_unspecified() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        local.ip()
    }
}

/// Branch parameter of a request's top Via header (string-level, robust).
fn via_branch(req: &Request) -> Option<String> {
    let via = req.headers.get_all("Via").first()?.to_string();
    let i = via.find(";branch=")? + ";branch=".len();
    let rest = &via[i..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

async fn uri_to_socket(uri: &SipUri) -> Option<SocketAddr> {
    let port = uri.port.unwrap_or(5060);
    match &uri.host {
        Host::Ipv4(ip) => Some(SocketAddr::new(std::net::IpAddr::V4(*ip), port)),
        Host::Ipv6(ip) => Some(SocketAddr::new(std::net::IpAddr::V6(*ip), port)),
        Host::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await
            .ok()?
            .next(),
    }
}

fn extract_uri(contact: &str) -> Option<SipUri> {
    let inner = contact.trim().trim_start_matches('<').trim_end_matches('>');
    match SipUri::parse(inner) {
        Ok(u) => Some(u),
        Err(_) => contact
            .split('<')
            .nth(1)
            .and_then(|rest| rest.split('>').next())
            .and_then(|u| SipUri::parse(u).ok()),
    }
}

impl Leg {
    fn codec_name(&self) -> String {
        self.plan
            .as_ref()
            .and_then(|p| p.codec.clone())
            .map(|(n, _, _)| n)
            .unwrap_or_else(|| "?".into())
    }
}

/// Stops pumps, emits the terminal CDR and drops the call. Also clears the
/// leg-B Call-ID alias so the map cannot leak entries on CANCEL, dial
/// timeout, rejection or session expiry (only BYE used to clean it).
fn teardown(
    calls: &mut HashMap<String, Call>,
    b_to_a: &mut HashMap<String, String>,
    id: &str,
    reason: &str,
    code: Option<u16>,
) {
    b_to_a.retain(|_, v| v != id);
    if let Some(mut c) = calls.remove(id) {
        // leg-down tap for every leg that was up
        if c.leg_a.is_some() {
            observ::session::emit_for(
                id,
                observ::EventKind::B2buaLegDown {
                    side: "A".into(),
                    reason: reason.to_string(),
                },
            );
        }
        if c.leg_b.is_some() {
            observ::session::emit_for(
                id,
                observ::EventKind::B2buaLegDown {
                    side: "B".into(),
                    reason: reason.to_string(),
                },
            );
        }
        let duration = c.created.elapsed().as_millis() as u64;
        let a2b = c
            .leg_b
            .as_ref()
            .and_then(|l| l.media.as_ref())
            .map(|m| m.stats.frames_encoded())
            .unwrap_or(0);
        let b2a = c
            .leg_a
            .as_ref()
            .and_then(|l| l.media.as_ref())
            .map(|m| m.stats.frames_encoded())
            .unwrap_or(0);
        let concealed = c
            .leg_a
            .as_ref()
            .and_then(|l| l.media.as_ref())
            .map(|m| m.stats.frames_concealed())
            .unwrap_or(0)
            + c.leg_b
                .as_ref()
                .and_then(|l| l.media.as_ref())
                .map(|m| m.stats.frames_concealed())
                .unwrap_or(0);
        if let Some(a) = c.leg_a.as_mut() {
            if let Some(m) = a.media.take() {
                let _ = m.stop.send(true);
            }
        }
        if let Some(b) = c.leg_b.as_mut() {
            if let Some(m) = b.media.take() {
                let _ = m.stop.send(true);
            }
        }
        let _ = reason;
        cdr_log(
            c.a_answer.clone(),
            id.to_string(),
            duration,
            a2b,
            b2a,
            concealed,
            code,
        );
    }
}

// The CDR emission is factored through a stored sender installed at run() —
// module-level to avoid plumbing it through every call site.
static CDR_SINK: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<CdrEvent>> =
    std::sync::OnceLock::new();

fn cdr_log(
    _answer: String,
    call_id: String,
    duration_ms: u64,
    a2b: u64,
    b2a: u64,
    concealed: u64,
    final_code: Option<u16>,
) {
    if let Some(sink) = CDR_SINK.get() {
        let _ = sink.send(CdrEvent::CallEnded {
            call_id,
            duration_ms,
            frames_a_to_b: a2b,
            frames_b_to_a: b2a,
            concealed,
            final_code,
            at: Instant::now(),
        });
    }
}

impl B2bua {
    /// Registers the process-wide CDR sink used by `teardown`.
    fn install_sink(&self) {
        let _ = CDR_SINK.set(self.cdr.clone());
    }
}

impl B2bua {
    /// Counters shared with the run loop (exposed for tests/demos).
    pub fn stats_handle(
    ) -> &'static std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<CdrEvent>> {
        &CDR_SINK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::uri::TransportKind;

    /// The CANCEL for an outstanding INVITE mirrors the Request-URI, the
    /// top Via verbatim (so sent-by + branch match the INVITE transaction),
    /// From/To/Call-ID, the INVITE's CSeq number with method CANCEL and the
    /// Route set (RFC 3261 §9.1).
    #[test]
    fn build_cancel_matches_the_invite_transaction() {
        let mut invite = RequestBuilder::new(
            Method::Invite,
            SipUri::parse("sip:1000@10.1.2.3:5070").unwrap(),
        )
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKdial"))
        .from("<sip:zrtc@10.0.0.9>;tag=ourtag")
        .to("<sip:1000@gw>")
        .call_id(Some("call-1"))
        .cseq(7)
        .header("Route", "<sip:proxyA;lr>")
        .build();
        invite.headers.add("Route", "<sip:proxyB;lr>");

        let cancel = build_cancel(&invite);
        assert_eq!(cancel.method, Method::Cancel);
        assert_eq!(cancel.uri, invite.uri);
        // Top Via copied verbatim: identical sent-by AND branch.
        assert_eq!(cancel.headers.get("Via"), invite.headers.get("Via"));
        assert_eq!(via_branch(&cancel).as_deref(), Some("z9hG4bKdial"));
        // From/To/Call-ID mirrored, CSeq kept with method CANCEL.
        assert_eq!(
            cancel.headers.get("From"),
            Some("<sip:zrtc@10.0.0.9>;tag=ourtag")
        );
        assert_eq!(cancel.headers.get("To"), Some("<sip:1000@gw>"));
        assert_eq!(cancel.headers.call_id(), Some("call-1"));
        let cseq = cancel.headers.cseq().unwrap();
        assert_eq!(cseq.seq, 7);
        assert_eq!(cseq.method, Method::Cancel);
        // Route set carried over in order.
        assert_eq!(
            cancel.headers.get_all("Route"),
            vec!["<sip:proxyA;lr>", "<sip:proxyB;lr>"]
        );
    }
}
