//! Server-Sent Events transport for canonical replay/live delivery.
//!
//! Per ADR-0013 and SSE_PROTOCOL.md: SSE is transport-only,
//! does not own state, and streams pre-authorized live events
//! with ackable cursors.

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Serialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::mpsc;

/// Versioned SSE transport envelope. Per SSE_PROTOCOL.md frame model.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SseDelivery {
    /// Transport protocol version (current: 1).
    pub transport_version: u32,
    /// Opaque session identifier.
    pub replay_session_id: String,
    /// Opaque live delivery identifier (None during catch-up).
    pub live_delivery_id: Option<String>,
    /// Monotonic delivery sequence within this session.
    pub delivery_sequence: u64,
    /// The canonical event (serialized JSON envelope).
    pub canonical_event: serde_json::Value,
    /// The opaque ackable replay cursor.
    pub replay_cursor: String,
}

/// Terminal frame sent before stream close on error.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SseTerminalFrame {
    /// Transport protocol version.
    pub transport_version: u32,
    /// Reason code: Unauthorized, SensitivityDenied, UnsupportedSchema,
    /// RetentionGap, BackpressureExceeded, SessionClosed.
    pub reason: String,
    /// Redacted diagnostic (no secrets, no payload).
    pub message: String,
}

/// SSE delivery item — either a live event or a terminal frame.
#[derive(Clone, Debug)]
pub enum SseItem {
    /// A canonical event delivery.
    Delivery(SseDelivery),
    /// Terminal error frame (stream closes after this).
    Terminal(SseTerminalFrame),
    /// Heartbeat (no data, keeps connection alive).
    Heartbeat,
}

/// Bounded capacity for the SSE channel (per ADR-0013: bounded buffer).
const DEFAULT_SSE_CHANNEL_CAPACITY: usize = 256;

/// Create a bounded mpsc channel for SSE delivery items.
pub fn sse_channel(capacity: usize) -> (mpsc::Sender<SseItem>, mpsc::Receiver<SseItem>) {
    mpsc::channel(capacity.max(1))
}

/// Create a bounded mpsc channel with the default capacity.
pub fn default_sse_channel() -> (mpsc::Sender<SseItem>, mpsc::Receiver<SseItem>) {
    sse_channel(DEFAULT_SSE_CHANNEL_CAPACITY)
}

/// Convert an mpsc receiver into an Axum SSE stream.
///
/// Heartbeats are sent every `heartbeat_interval`. The stream
/// terminates when the sender is dropped or a Terminal frame
/// arrives. Slow consumers trigger backpressure on the sender.
pub fn into_sse_stream(
    mut rx: mpsc::Receiver<SseItem>,
    heartbeat_interval: Duration,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        loop {
            match tokio::time::timeout(heartbeat_interval, rx.recv()).await {
                Ok(Some(SseItem::Delivery(delivery))) => {
                    let json = serde_json::to_string(&delivery)
                        .expect("SSE delivery contains only serializable values");
                    yield Ok(Event::default()
                        .data(json)
                        .event("delivery"));
                }
                Ok(Some(SseItem::Terminal(terminal))) => {
                    let json = serde_json::to_string(&terminal)
                        .expect("SSE terminal frame contains only serializable values");
                    yield Ok(Event::default()
                        .data(json)
                        .event("terminal"));
                    break;
                }
                Ok(Some(SseItem::Heartbeat)) => {
                    yield Ok(Event::default().comment("ping"));
                }
                Ok(None) => {
                    break;
                }
                Err(_elapsed) => {
                    yield Ok(Event::default().comment("ping"));
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
