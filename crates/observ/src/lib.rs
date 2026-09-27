//! # observ — in-process observability for the zrtc stack
//!
//! Everything is correlated by SIP Call-ID and flows through one
//! [`bus::EventBus`]:
//!
//! ```text
//! hooks (sip transport, sbc, proxy, registrar, b2bua, media, ai-bridge, cdr)
//!      │  publish Event
//!      ▼
//!  EventBus (tokio broadcast)
//!      ├── writer 1 → sip.pcap   (manual classic-pcap: Eth/IP/UDP framing)
//!      ├── writer 2 → rtp.pcap   (manual classic-pcap)
//!      └── writer 3 → trace-YYYYMMDD.log + .jsonl + status.json
//! ```
//!
//! Producers use the global bus (`bus::install_global` + the tap helpers in
//! [`session`]); consumers are spawned by [`spawn::spawn_writers`]. Pcap
//! files are written byte-by-byte here — no libpcap — yet Wireshark decodes
//! SIP and RTP natively. Authorization headers are redacted at the tap, so
//! no sink can ever see them.

pub mod bus;
pub mod event;
pub mod pcap_sink;
pub mod session;
pub mod spawn;
pub mod trace_sink;

pub use bus::EventBus;
pub use event::{Event, EventKind};
pub use session::CallSession;
