//! Server-Sent Events (SSE) streaming for live event delivery.
//!
//! Provides utilities for creating broadcast channels and converting
//! them into Axum SSE streams with heartbeat support.

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Serialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast;

/// SSE event data.
#[derive(Clone, Debug, Serialize)]
pub struct LiveEvent {
    pub global_position: i64,
    pub event_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
}

/// Create an SSE stream from a broadcast receiver.
///
/// Yields `LiveEvent` JSON as `event:` frames, with a heartbeat every
/// `heartbeat_interval` when no events are available.
pub fn sse_stream(
    mut rx: broadcast::Receiver<LiveEvent>,
    heartbeat_interval: Duration,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        loop {
            match tokio::time::timeout(heartbeat_interval, rx.recv()).await {
                Ok(Ok(event)) => {
                    let json = serde_json::to_string(&event).unwrap_or_default();
                    yield Ok(Event::default().data(json).event("event"));
                }
                Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!(skipped = n, "SSE lagged");
                    yield Ok(Event::default().event("lagged").data(format!("{}", n)));
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    break;
                }
                Err(_) => {
                    // timeout — send heartbeat
                    yield Ok(Event::default().event("heartbeat").data("ping"));
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Create a broadcast channel for live events.
pub fn live_event_channel(
    capacity: usize,
) -> (broadcast::Sender<LiveEvent>, broadcast::Receiver<LiveEvent>) {
    broadcast::channel(capacity)
}
