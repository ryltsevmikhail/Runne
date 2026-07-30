//! Bounded Server-Sent Events transport for canonical replay/live delivery.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::limits::{
    MAX_LIVE_QUEUE_FRAMES, ReplayQueuePermit, ReplayQueueQuota, ReplayQuotaManager,
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SseDelivery {
    pub transport_version: u32,
    pub replay_session_id: String,
    pub live_delivery_id: Option<String>,
    pub delivery_sequence: u64,
    pub canonical_event: serde_json::Value,
    pub replay_cursor: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SseTerminalFrame {
    pub transport_version: u32,
    pub code: String,
}

#[derive(Clone, Debug)]
pub enum SseItem {
    Delivery(SseDelivery),
    Terminal(SseTerminalFrame),
    Heartbeat,
}

struct QueuedSseItem {
    item: SseItem,
    _bytes: ReplayQueuePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SseSendError {
    Backpressure,
    Closed,
}

#[derive(Clone)]
pub struct SseSender {
    sender: mpsc::Sender<QueuedSseItem>,
    quota: ReplayQueueQuota,
}

impl SseSender {
    pub fn try_send(&self, item: SseItem) -> Result<(), SseSendError> {
        let frame_bytes = encoded_frame_bytes(&item).map_err(|_| SseSendError::Backpressure)?;
        let reservation = self
            .quota
            .reserve(frame_bytes)
            .map_err(|_| SseSendError::Backpressure)?;
        self.sender
            .try_send(QueuedSseItem {
                item,
                _bytes: reservation,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SseSendError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => SseSendError::Closed,
            })
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

pub struct SseReceiver {
    receiver: mpsc::Receiver<QueuedSseItem>,
}

pub fn sse_channel(capacity: usize) -> (SseSender, SseReceiver) {
    sse_channel_with_quota(
        capacity.min(MAX_LIVE_QUEUE_FRAMES),
        ReplayQuotaManager::default().queue(),
    )
}

pub fn sse_channel_with_quota(
    capacity: usize,
    quota: ReplayQueueQuota,
) -> (SseSender, SseReceiver) {
    let (sender, receiver) = mpsc::channel(capacity.clamp(1, MAX_LIVE_QUEUE_FRAMES));
    (SseSender { sender, quota }, SseReceiver { receiver })
}

fn encoded_frame_bytes(item: &SseItem) -> Result<usize, serde_json::Error> {
    match item {
        SseItem::Delivery(delivery) => serde_json::to_vec(delivery).map(|json| {
            b"event: delivery\ndata: \n\n"
                .len()
                .saturating_add(json.len())
        }),
        SseItem::Terminal(terminal) => serde_json::to_vec(terminal).map(|json| {
            b"event: terminal\ndata: \n\n"
                .len()
                .saturating_add(json.len())
        }),
        SseItem::Heartbeat => Ok(b": ping\n\n".len()),
    }
}

pub fn into_sse_stream(
    mut rx: SseReceiver,
    heartbeat_interval: Duration,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        loop {
            match tokio::time::timeout(heartbeat_interval, rx.receiver.recv()).await {
                Ok(Some(queued)) => match queued.item {
                    SseItem::Delivery(delivery) => {
                        let json = serde_json::to_string(&delivery)
                            .expect("SSE delivery contains only serializable values");
                        yield Ok(Event::default().data(json).event("delivery"));
                    }
                    SseItem::Terminal(terminal) => {
                        let json = serde_json::to_string(&terminal)
                            .expect("SSE terminal contains only serializable values");
                        yield Ok(Event::default().data(json).event("terminal"));
                        break;
                    }
                    SseItem::Heartbeat => {
                        yield Ok(Event::default().comment("ping"));
                    }
                },
                Ok(None) => break,
                Err(_elapsed) => {
                    yield Ok(Event::default().comment("ping"));
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
