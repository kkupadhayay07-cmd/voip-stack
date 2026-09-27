//! The in-process event bus: a tokio broadcast channel with drop accounting.
//! Writers (pcap/trace) subscribe; producers publish and never block.

use crate::event::Event;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Fan-out hub for [`Event`]s. Cloning is cheap (`Arc` inside is not needed —
/// the channel sender is already cloneable and `publish` takes `&self`).
pub struct EventBus {
    tx: broadcast::Sender<Event>,
    published: AtomicU64,
    dropped: AtomicU64,
}

impl EventBus {
    /// `capacity` = how many events a slow subscriber may lag behind before
    /// it starts seeing `RecvError::Lagged` (those drops are accounted by the
    /// subscriber, not here).
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        EventBus {
            tx,
            published: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Publishes an event to all current subscribers. Never blocks; sending
    /// with zero subscribers or a full channel counts as dropped.
    pub fn publish(&self, ev: Event) {
        self.published.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Subscribes a writer.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Events dropped because no subscriber was attached (or the channel
    /// was full).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Total events accepted by the bus.
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }
}

static GLOBAL: std::sync::OnceLock<Arc<EventBus>> = std::sync::OnceLock::new();

/// Installs the process-global bus (hooks across crates publish into it).
/// Returns `false` when a bus was already installed.
pub fn install_global(bus: Arc<EventBus>) -> bool {
    GLOBAL.set(bus).is_ok()
}

/// The process-global bus, if installed.
pub fn global() -> Option<Arc<EventBus>> {
    GLOBAL.get().cloned()
}

/// Publishes to the global bus when present; no-op otherwise (tests, and
/// processes running without observability).
pub fn emit(ev: Event) {
    if let Some(bus) = global() {
        bus.publish(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, Leg};

    #[tokio::test]
    async fn pubsub_and_drop_accounting() {
        let bus = Arc::new(EventBus::new(4));
        let mut rx = bus.subscribe();
        bus.publish(Event {
            ts_ms: 1,
            call_id: "c".into(),
            trunk: None,
            direction: None,
            leg: Leg::Core,
            kind: EventKind::Vad { state: "x".into() },
        });
        let got = rx.recv().await.unwrap();
        assert_eq!(got.call_id, "c");
        assert_eq!(bus.published(), 1);
        assert_eq!(bus.dropped(), 0);

        // No subscriber attached → dropped.
        let bus2 = EventBus::new(4);
        bus2.publish(Event::now("d", EventKind::Vad { state: "y".into() }));
        assert_eq!(bus2.dropped(), 1);
        assert_eq!(bus2.published(), 1);
    }

    #[tokio::test]
    async fn lagged_receiver_is_told_how_many_it_missed() {
        let bus = Arc::new(EventBus::new(2));
        let mut rx = bus.subscribe();
        for i in 0..6 {
            bus.publish(Event::now(format!("c{i}"), EventKind::Vad { state: "s".into() }));
        }
        assert!(matches!(rx.recv().await, Err(broadcast::error::RecvError::Lagged(n)) if n >= 1));
        assert!(rx.recv().await.is_ok(), "channel continues after lag");
    }
}
