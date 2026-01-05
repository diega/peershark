use crate::events::ProxyEvent;
use tokio::sync::broadcast;

/// Capacity of the event bus channel.
/// Events are dropped if subscribers can't keep up.
const EVENT_BUS_CAPACITY: usize = 1024;

/// Central event bus for proxy events.
///
/// Uses tokio broadcast channel for multi-producer multi-consumer communication.
/// External consumers can subscribe to receive events about tunnel activity.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ProxyEvent>,
}

impl EventBus {
    /// Creates a new event bus with default capacity.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        Self { sender }
    }

    /// Subscribes to events from this bus.
    /// Returns a receiver that will get all events emitted after subscription.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.sender.subscribe()
    }

    /// Emits an event to all subscribers.
    /// Returns the number of receivers that received the event.
    /// Returns 0 if there are no active subscribers (this is not an error).
    pub fn emit(&self, event: ProxyEvent) -> usize {
        // send() returns Err if there are no receivers, which is fine
        self.sender.send(event).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Direction, Protocol};

    #[tokio::test]
    async fn emit_with_no_subscribers_returns_zero() {
        let bus = EventBus::new();
        let event = ProxyEvent::PeerConnected {
            tunnel_id: "test".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            client_id: "test".to_string(),
            remote_enode: "test".to_string(),
            network_id: 1,
            fork_hash: "fc64ec04".to_string(),
            fork_next: 0,
            capabilities: vec![],
            timestamp: 0,
        };
        assert_eq!(bus.emit(event), 0);
    }

    #[tokio::test]
    async fn single_subscriber_receives_event() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let event = ProxyEvent::PeerConnected {
            tunnel_id: "test".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            client_id: "test".to_string(),
            remote_enode: "test".to_string(),
            network_id: 1,
            fork_hash: "fc64ec04".to_string(),
            fork_next: 0,
            capabilities: vec![],
            timestamp: 12345,
        };

        let sent = bus.emit(event);
        assert_eq!(sent, 1);

        let received = rx.recv().await.unwrap();
        match received {
            ProxyEvent::PeerConnected { timestamp, .. } => {
                assert_eq!(timestamp, 12345);
            }
            _ => panic!("wrong event type"),
        }
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_event() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = ProxyEvent::MessageRelayed {
            tunnel_id: "t1".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            direction: Direction::ClientToPeer,
            msg_id: 0x10,
            msg_name: "Status".to_string(),
            protocol: Protocol::Eth,
            size: 100,
            decoded: None,
            raw: None,
            timestamp: 999,
        };

        let sent = bus.emit(event);
        assert_eq!(sent, 2);

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        // Both should receive the same event
        match (&e1, &e2) {
            (
                ProxyEvent::MessageRelayed { tunnel_id: t1, .. },
                ProxyEvent::MessageRelayed { tunnel_id: t2, .. },
            ) => {
                assert_eq!(t1, "t1");
                assert_eq!(t2, "t1");
            }
            _ => panic!("wrong event types"),
        }
    }
}
