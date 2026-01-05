//! WebSocket handler with event subscriptions and filtering.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tracing::debug;

use crate::events::{ProxyEvent, now_millis};

use super::filter::{FilterExpr, FilterParseError, Subscription};
use super::state::ApiState;

/// Message sent from server to client.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Initial state on connection.
    State {
        collecting_since: i64,
        tunnels: Vec<super::state::TunnelSnapshot>,
        msgs_per_sec: f64,
    },
    /// Live event (either lifecycle or filtered traffic).
    Event { data: ProxyEvent },
    /// Subscription confirmed.
    Subscribed {
        filter_description: String,
        include_raw: bool,
    },
    /// Filter updated successfully.
    FilterUpdated { filter_description: String },
    /// Error response.
    Error { code: String, message: String },
    /// Gap notification for missed events due to client lag.
    Gap { from: i64, to: i64, reason: String },
}

/// Command from client to server.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ClientCommand {
    /// Subscribe to events with optional filter.
    Subscribe {
        /// Filter expression (e.g., "protocol == \"eth\" && size > 1000").
        /// If None or empty, receives all MessageRelayed events.
        filter: Option<String>,
        /// Whether to include raw bytes in MessageRelayed events.
        #[serde(default)]
        include_raw: Option<bool>,
    },
    /// Update the current filter without resubscribing.
    SetFilter {
        /// New filter expression.
        filter: String,
    },
    /// Unsubscribe from MessageRelayed events (keep connection for lifecycle events).
    Unsubscribe,
}

/// Handle a WebSocket connection.
pub async fn handle_socket(
    socket: WebSocket,
    state: ApiState,
    event_rx: broadcast::Receiver<ProxyEvent>,
) {
    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(RwLock::new(sender));

    // Send initial state
    let snapshot = state.snapshot().await;
    let init_msg = ServerMessage::State {
        collecting_since: snapshot.collecting_since,
        tunnels: snapshot.tunnels,
        msgs_per_sec: snapshot.msgs_per_sec,
    };

    {
        let mut sender_guard = sender.write().await;
        if let Ok(json) = serde_json::to_string(&init_msg)
            && sender_guard.send(Message::Text(json)).await.is_err()
        {
            return;
        }
    }

    // Subscription state: None means not subscribed to MessageRelayed events
    let subscription: Arc<RwLock<Option<Subscription>>> = Arc::new(RwLock::new(None));

    // Spawn event relay task
    let relay_sender = sender.clone();
    let relay_sub = subscription.clone();
    let relay_rate = state.global_rate.clone();
    let mut event_rx = event_rx;

    let relay_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    // For MessageRelayed: always send TrafficTick, optionally send full event
                    if let ProxyEvent::MessageRelayed {
                        ref tunnel_id,
                        direction,
                        size,
                        timestamp,
                        ..
                    } = event
                    {
                        // Record message and get current rate
                        relay_rate.record();
                        let rate = relay_rate.rate();

                        // Always send TrafficTick (extracted from MessageRelayed)
                        let tick = ProxyEvent::TrafficTick {
                            tunnel_id: tunnel_id.clone(),
                            direction,
                            size,
                            msgs_per_sec: rate,
                            timestamp,
                        };
                        let tick_msg = ServerMessage::Event { data: tick };
                        if let Ok(json) = serde_json::to_string(&tick_msg) {
                            let mut sender_guard = relay_sender.write().await;
                            if sender_guard.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }

                        // Send full MessageRelayed only if subscribed and filter matches
                        let (should_send_full, include_raw) = {
                            let mut sub_guard = relay_sub.write().await;
                            if let Some(ref mut sub) = *sub_guard {
                                sub.last_event_ts = Some(timestamp);
                                (sub.filter.matches(&event), sub.include_raw)
                            } else {
                                (false, false)
                            }
                        };

                        if should_send_full {
                            let mut event_to_send = event;
                            if !include_raw
                                && let ProxyEvent::MessageRelayed { ref mut raw, .. } =
                                    event_to_send
                            {
                                *raw = None;
                            }
                            let msg = ServerMessage::Event {
                                data: event_to_send,
                            };
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let mut sender_guard = relay_sender.write().await;
                                if sender_guard.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    } else {
                        // Lifecycle events: always send
                        let msg = ServerMessage::Event { data: event };
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let mut sender_guard = relay_sender.write().await;
                            if sender_guard.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Buffer overflow - notify client of gap
                    let (from_ts, to_ts) = {
                        let sub_guard = relay_sub.read().await;
                        let from = sub_guard
                            .as_ref()
                            .and_then(|s| s.last_event_ts)
                            .unwrap_or(0);
                        (from, now_millis())
                    };

                    let gap_msg = ServerMessage::Gap {
                        from: from_ts,
                        to: to_ts,
                        reason: format!("buffer overflow: {} events dropped", n),
                    };

                    if let Ok(json) = serde_json::to_string(&gap_msg) {
                        let mut sender_guard = relay_sender.write().await;
                        if sender_guard.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    // Handle incoming messages
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                let response = match serde_json::from_str::<ClientCommand>(&text) {
                    Ok(cmd) => {
                        debug!(?cmd, "received client command");
                        handle_command(cmd, &subscription).await
                    }
                    Err(e) => Some(ServerMessage::Error {
                        code: "invalid_command".to_string(),
                        message: e.to_string(),
                    }),
                };

                if let Some(resp) = response
                    && let Ok(json) = serde_json::to_string(&resp)
                {
                    let mut sender_guard = sender.write().await;
                    if sender_guard.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
            Message::Close(_) => {
                debug!("client closed connection");
                break;
            }
            _ => {}
        }
    }

    relay_task.abort();
}

/// Handle a client command and return an optional response.
async fn handle_command(
    cmd: ClientCommand,
    subscription: &Arc<RwLock<Option<Subscription>>>,
) -> Option<ServerMessage> {
    match cmd {
        ClientCommand::Subscribe {
            filter,
            include_raw,
        } => {
            let filter_str = filter.unwrap_or_default();
            let include_raw = include_raw.unwrap_or(false);

            match parse_filter(&filter_str) {
                Ok((expr, description)) => {
                    let mut sub_guard = subscription.write().await;
                    *sub_guard = Some(Subscription {
                        filter: expr,
                        filter_description: description.clone(),
                        include_raw,
                        last_event_ts: None,
                    });

                    Some(ServerMessage::Subscribed {
                        filter_description: description,
                        include_raw,
                    })
                }
                Err(e) => Some(ServerMessage::Error {
                    code: error_code_from_parse_error(&e),
                    message: e.to_string(),
                }),
            }
        }

        ClientCommand::SetFilter { filter } => {
            let mut sub_guard = subscription.write().await;

            if sub_guard.is_none() {
                return Some(ServerMessage::Error {
                    code: "not_subscribed".to_string(),
                    message: "Must subscribe before setting filter".to_string(),
                });
            }

            match parse_filter(&filter) {
                Ok((expr, description)) => {
                    if let Some(ref mut sub) = *sub_guard {
                        sub.filter = expr;
                        sub.filter_description = description.clone();
                    }

                    Some(ServerMessage::FilterUpdated {
                        filter_description: description,
                    })
                }
                Err(e) => Some(ServerMessage::Error {
                    code: error_code_from_parse_error(&e),
                    message: e.to_string(),
                }),
            }
        }

        ClientCommand::Unsubscribe => {
            let mut sub_guard = subscription.write().await;
            *sub_guard = None;
            // No response needed for unsubscribe
            None
        }
    }
}

/// Parse a filter string and return the expression and description.
fn parse_filter(filter_str: &str) -> Result<(FilterExpr, String), FilterParseError> {
    let trimmed = filter_str.trim();
    if trimmed.is_empty() {
        Ok((FilterExpr::True, "(all events)".to_string()))
    } else {
        let expr = FilterExpr::parse(trimmed)?;
        let description = expr.describe();
        Ok((expr, description))
    }
}

/// Map parse error to error code.
fn error_code_from_parse_error(e: &FilterParseError) -> String {
    if e.message.contains("exceeds") && e.message.contains("bytes") {
        "filter_too_long".to_string()
    } else if e.message.contains("depth") {
        "filter_too_complex".to_string()
    } else if e.message.contains("IN list exceeds") {
        "in_list_too_large".to_string()
    } else {
        "invalid_filter".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_message_serializes_correctly() {
        let msg = ServerMessage::Gap {
            from: 1000,
            to: 2000,
            reason: "buffer overflow".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("ServerMessage should serialize to JSON");
        assert!(json.contains("\"type\":\"gap\""));
        assert!(json.contains("\"from\":1000"));
    }

    #[test]
    fn subscribed_message_serializes() {
        let msg = ServerMessage::Subscribed {
            filter_description: "protocol == eth".to_string(),
            include_raw: false,
        };

        let json = serde_json::to_string(&msg).expect("Subscribed should serialize");
        assert!(json.contains("\"type\":\"subscribed\""));
        assert!(json.contains("protocol == eth"));
    }

    #[test]
    fn error_message_serializes() {
        let msg = ServerMessage::Error {
            code: "invalid_filter".to_string(),
            message: "Unknown field 'foo'".to_string(),
        };

        let json = serde_json::to_string(&msg).expect("Error should serialize");
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("invalid_filter"));
    }

    #[test]
    fn client_command_deserializes_subscribe() {
        let json = r#"{"cmd": "subscribe", "filter": "protocol == \"eth\""}"#;
        let cmd: ClientCommand = serde_json::from_str(json).expect("Should deserialize");
        assert!(matches!(cmd, ClientCommand::Subscribe { .. }));
    }

    #[test]
    fn client_command_deserializes_set_filter() {
        let json = r#"{"cmd": "set_filter", "filter": "size > 1000"}"#;
        let cmd: ClientCommand = serde_json::from_str(json).expect("Should deserialize");
        assert!(matches!(cmd, ClientCommand::SetFilter { .. }));
    }

    #[test]
    fn client_command_deserializes_unsubscribe() {
        let json = r#"{"cmd": "unsubscribe"}"#;
        let cmd: ClientCommand = serde_json::from_str(json).expect("Should deserialize");
        assert!(matches!(cmd, ClientCommand::Unsubscribe));
    }
}
