//! The B2BUA engine loop: SIP handling (UAS + UAC legs), call lifecycle and
//! pump orchestration. Single-owner state (no locks on the call map).

use crate::media::{self, PumpConfig, PumpHandle};
use crate::sdp_util;
use crate::{CdrEvent, Side};
use rand::Rng;
use sdp::negotiate::{stream_plans, StreamPlan};
use sip_core::builder::RequestBuilder;
use sip_core::ids::{new_branch, new_call_id, new_tag};
use sip_core::message::{Method, Request, Response, SipMessage};
use sip_core::uri::{Host, SipUri, TransportKind};
use sip_core::{parse_message, serialize};
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
        }
    }
}

const T1: Duration = Duration::from_millis(500);
const TIMER_B: Duration = Duration::from_millis(32_000);
const TICK: Duration = Duration::from_millis(200);

struct Leg {
    side: Side,
    call_id: String,
    local_tag: String,
    remote_tag: Option<String>,
    remote_sip: SocketAddr,
    /// Next CSeq we send as UAC (leg B only).
    next_cseq: u32,
    /// Leg A: the INVITE we received (source for responses).
    invite: Option<Request>,
    /// Peer Contact URI text (request-URI for in-dialog requests).
    contact: Option<String>,
    plan: Option<StreamPlan>,
    /// Bound RTP socket (A: bound on INVITE, B: bound on originate).
    rtp: Option<Arc<UdpSocket>>,
    media: Option<PumpHandle>,
    confirmed: bool,
}

struct PendingInvite {
    req: Vec<u8>,
    dst: SocketAddr,
    next_retrans: Instant,
    interval: Duration,
    deadline: Instant,
}

struct Call {
    leg_a: Option<Leg>,
    leg_b: Option<Leg>,
    pending: Option<PendingInvite>,
    /// SDP answer for leg A (sent with the 200).
    a_answer: String,
    created: Instant,
}

impl Call {
    fn new(a_answer: String) -> Self {
        Self {
            leg_a: None,
            leg_b: None,
            pending: None,
            a_answer,
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
                    Self::timers(&sock, &mut calls);
                }
            }
        }
    }

    fn timers(sock: &Arc<UdpSocket>, calls: &mut HashMap<String, Call>) {
        let now = Instant::now();

        // Timer B expiry.
        let expired: Vec<String> = calls
            .iter()
            .filter(|(_, c)| c.pending.as_ref().is_some_and(|p| now >= p.deadline))
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            tracing::warn!(call_id = %id, "outgoing INVITE timed out (Timer B)");
            if let Some(c) = calls.get_mut(&id) {
                c.pending = None;
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
                teardown(calls, &id, "Timer B");
            }
        }

        // INVITE retransmissions (Timer A, doubling, capped at T2).
        let due: Vec<(String, Vec<u8>, SocketAddr)> = calls
            .iter()
            .filter_map(|(id, c)| {
                let p = c.pending.as_ref()?;
                (now >= p.next_retrans).then(|| (id.clone(), p.req.clone(), p.dst))
            })
            .collect();
        for (id, req, dst) in due {
            if let Some(c) = calls.get_mut(&id) {
                if let Some(p) = c.pending.as_mut() {
                    p.interval = (p.interval * 2).min(Duration::from_secs(4));
                    p.next_retrans = Instant::now() + p.interval;
                    let sock = sock.clone();
                    tokio::spawn(async move {
                        let _ = sock.send_to(&req, dst).await;
                    });
                }
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
                    Method::Ack => self.on_ack(calls, &call_id),
                    Method::Bye => self.on_bye(sock, calls, b_to_a, &req, call_id, src).await,
                    Method::Cancel => self.on_cancel(sock, calls, &req, call_id, src).await,
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
                    return;
                };
                let class = resp.code / 100;
                if class == 1 {
                    return;
                }
                let Some(call) = calls.get_mut(&a_id) else {
                    return;
                };
                let Some(_pending) = call.pending.take() else {
                    // Late 2xx retransmission: re-ACK.
                    if class == 2 {
                        if let Some(b) = call.leg_b.as_ref() {
                            self.send_ack(sock, b, &resp);
                        }
                    }
                    return;
                };
                if class == 2 {
                    self.on_b_answered(sock, local, calls, &a_id, &call_id, resp)
                        .await;
                } else {
                    tracing::info!(call_id = %a_id, "leg B failed with {}", resp.code);
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
                                .send_to(&serialize(&SipMessage::Response(fail)), a.remote_sip)
                                .await;
                        }
                    }
                    teardown(calls, &a_id, "leg B rejected");
                }
            }
        }
    }

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
        // Retransmitted INVITE for an existing call → resend cached 200.
        if let Some(c) = calls.get_mut(&call_id) {
            let resent = c.leg_a.as_ref().and_then(|a| {
                let invite = a.invite.as_ref()?;
                (via_branch(invite) == via_branch(&req)).then(|| {
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
                return;
            }
        }
        if calls.contains_key(&call_id) {
            return; // re-INVITE: Phase 1 does not renegotiate
        }

        // SDP offer required.
        let offer = match sdp::parse::parse(&String::from_utf8_lossy(&req.body)) {
            Ok(o) => o,
            Err(e) => {
                tracing::info!(%call_id, "INVITE without valid SDP: {e}");
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
        };

        let _ = sock
            .send_to(
                &serialize(&SipMessage::Response(sip_core::builder::respond_to(
                    &req,
                    100,
                    "Trying",
                    Vec::new(),
                    None,
                ))),
                src,
            )
            .await;

        // Bind leg A media socket and build the answer.
        let Ok(a_sock) = UdpSocket::bind(("0.0.0.0", self.cfg.media_base_port)).await else {
            tracing::error!(%call_id, "media bind failed");
            return;
        };
        let a_sock = Arc::new(a_sock);
        let a_port = a_sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let answer = match sdp_util::answer(&offer, &self.cfg.media_host, a_port, &self.cfg.codecs)
        {
            Ok(ans) => ans,
            Err(e) => {
                tracing::info!(%call_id, "SDP negotiation failed: {e:?}");
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
        };
        let a_plan = stream_plans(&answer).into_iter().next();

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

        // UAC INVITE.
        let b_call_id = new_call_id("b2bua.local");
        let b_tag = new_tag();
        let branch = new_branch();
        let invite = RequestBuilder::new(Method::Invite, target_uri.clone())
            .via(TransportKind::Udp, &local.to_string(), Some(&branch))
            .from(&format!("<sip:zrtc@{}>;tag={b_tag}", local_ip(local)))
            .to(&format!("<{target}>"))
            .call_id(Some(&b_call_id))
            .cseq(1)
            .contact(&format!("<sip:zrtc@{}>", local_ip(local)))
            .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS")
            .body("application/sdp", offer_b.into_bytes())
            .build();
        let req_bytes = serialize(&SipMessage::Request(invite));

        // 180 Ringing to A.
        let _ = sock
            .send_to(
                &serialize(&SipMessage::Response(sip_core::builder::respond_to(
                    &req,
                    180,
                    "Ringing",
                    Vec::new(),
                    None,
                ))),
                src,
            )
            .await;

        let mut call = Call::new(answer.serialize());
        let leg_a = Leg {
            side: Side::A,
            call_id: call_id.clone(),
            local_tag: new_tag(),
            remote_tag: from_tag,
            remote_sip: src,
            next_cseq: 0,
            invite: Some(req),
            contact,
            plan: a_plan,
            rtp: Some(a_sock),
            media: None,
            confirmed: false,
        };
        call.leg_a = Some(leg_a);
        call.pending = Some(PendingInvite {
            req: req_bytes,
            dst,
            next_retrans: Instant::now() + T1,
            interval: T1,
            deadline: Instant::now() + TIMER_B,
        });
        call.leg_b = Some(Leg {
            side: Side::B,
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

    async fn on_b_answered(
        &self,
        sock: &Arc<UdpSocket>,
        local: SocketAddr,
        calls: &mut HashMap<String, Call>,
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
                teardown(calls, a_id, "bad SDP from leg B");
                return;
            }
        }
        if let Some(b) = call.leg_b.as_ref() {
            self.send_ack(sock, b, &resp);
        }

        self.cdr
            .send(CdrEvent::LegAnswered {
                call_id: a_id.to_string(),
                side: Side::B,
                codec: call.leg_b.as_ref().map(Leg::codec_name).unwrap_or_default(),
                at: Instant::now(),
            })
            .ok();
        self.cdr
            .send(CdrEvent::LegConfirmed {
                call_id: a_id.to_string(),
                side: Side::B,
                at: Instant::now(),
            })
            .ok();

        // Confirm A with 200 (cached for INVITE retransmission).
        let (a_snapshot, bytes) = {
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
            response.headers.add("Supported", "timer");
            let bytes = serialize(&SipMessage::Response(response));
            let snapshot = (a.local_tag.clone(), a.remote_sip);
            (snapshot, bytes)
        };
        let _ = sock.send_to(&bytes, a_snapshot.1).await;

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
                        };
                        let cfg_b = PumpConfig {
                            rx_codec: cb,
                            tx_codec: cb,
                            rx_pt: pb.local_pt,
                            te_pt_rx: pb.telephone_event_pt,
                            te_pt_tx: pb.telephone_event_pt,
                            tx_pt: pb.local_pt,
                        };
                        // Cross-connect the pumps: A's decoded bridge PCM feeds
                        // B's encoder and vice versa.
                        let (a_out, b_in) = tokio::sync::mpsc::channel(64);
                        let (b_out, a_in) = tokio::sync::mpsc::channel(64);
                        match (
                            media::start_with_socket(cfg_a, a_sock, a_out, a_in),
                            media::start_with_socket(cfg_b, b_sock, b_out, b_in),
                        ) {
                            (Ok(ha), Ok(hb)) => {
                                seed_remote(&ha, &pa).await;
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
        let _ = b_id;
    }

    fn on_ack(&self, calls: &mut HashMap<String, Call>, call_id: &str) {
        if let Some(c) = calls.get_mut(call_id) {
            if let Some(a) = c.leg_a.as_mut() {
                if !a.confirmed {
                    a.confirmed = true;
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
                c.leg_a.as_ref()
            } else {
                c.leg_b.as_ref()
            };
            if let Some(o) = other {
                let req_uri = o
                    .contact
                    .clone()
                    .and_then(|c| extract_uri(&c))
                    .unwrap_or_else(|| {
                        SipUri::parse(&format!("sip:peer@{}", o.remote_sip)).unwrap()
                    });
                let bye = RequestBuilder::new(Method::Bye, req_uri)
                    .via(
                        TransportKind::Udp,
                        &o.remote_sip.to_string(),
                        Some(&new_branch()),
                    )
                    .from(&format!("<sip:zrtc@b2bua>;tag={}", o.local_tag))
                    .to(&format!(
                        "<sip:peer>;tag={}",
                        o.remote_tag.clone().unwrap_or_default()
                    ))
                    .call_id(Some(&o.call_id))
                    .cseq(if from_b { 1 } else { o.next_cseq })
                    .build();
                let bytes = serialize(&SipMessage::Request(bye));
                let _ = sock.send_to(&bytes, o.remote_sip).await;
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
        teardown(calls, &a_id, "BYE");
        b_to_a.retain(|_, v| v != &a_id);
    }

    async fn on_cancel(
        &self,
        sock: &Arc<UdpSocket>,
        calls: &mut HashMap<String, Call>,
        req: &Request,
        call_id: String,
        src: SocketAddr,
    ) {
        let resp = sip_core::builder::respond_to(req, 200, "OK", Vec::new(), None);
        let _ = sock
            .send_to(&serialize(&SipMessage::Response(resp)), src)
            .await;
        if let Some(c) = calls.get_mut(&call_id) {
            if let Some(a) = &c.leg_a {
                if let Some(invite) = &a.invite {
                    let resp487 = sip_core::builder::respond_to(
                        invite,
                        487,
                        "Request Terminated",
                        Vec::new(),
                        None,
                    );
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp487)), a.remote_sip)
                        .await;
                }
            }
        }
        teardown(calls, &call_id, "CANCEL");
    }

    fn send_ack(&self, sock: &Arc<UdpSocket>, b: &Leg, _resp200: &Response) {
        let req_uri = b
            .contact
            .clone()
            .and_then(|c| extract_uri(&c))
            .unwrap_or_else(|| SipUri::parse(&format!("sip:peer@{}", b.remote_sip)).unwrap());
        let ack = RequestBuilder::new(Method::Ack, req_uri)
            .via(
                TransportKind::Udp,
                &b.remote_sip.to_string(),
                Some(&new_branch()),
            )
            .from(&format!("<sip:zrtc@b2bua>;tag={}", b.local_tag))
            .to(&format!(
                "<sip:peer>;tag={}",
                b.remote_tag.clone().unwrap_or_default()
            ))
            .call_id(Some(&b.call_id))
            .cseq(if b.next_cseq > 1 { b.next_cseq - 1 } else { 1 })
            .build();
        let bytes = serialize(&SipMessage::Request(ack));
        let sock = sock.clone();
        let dst = b.remote_sip;
        tokio::spawn(async move {
            let _ = sock.send_to(&bytes, dst).await;
        });
    }
}

// ---- helpers ---------------------------------------------------------------

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

/// Stops pumps, emits the terminal CDR and drops the call.
fn teardown(calls: &mut HashMap<String, Call>, id: &str, reason: &str) {
    if let Some(mut c) = calls.remove(id) {
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
        );
    }
}

// The CDR emission is factored through a stored sender installed at run() —
// module-level to avoid plumbing it through every call site.
static CDR_SINK: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<CdrEvent>> =
    std::sync::OnceLock::new();

fn cdr_log(_answer: String, call_id: String, duration_ms: u64, a2b: u64, b2a: u64, concealed: u64) {
    if let Some(sink) = CDR_SINK.get() {
        let _ = sink.send(CdrEvent::CallEnded {
            call_id,
            duration_ms,
            frames_a_to_b: a2b,
            frames_b_to_a: b2a,
            at: Instant::now(),
        });
        let _ = concealed;
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
