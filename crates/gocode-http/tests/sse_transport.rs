use std::time::Duration;

use axum::response::IntoResponse;
use futures::StreamExt;
use gocode_http::sse::{SseDelivery, SseItem, SseTerminalFrame, into_sse_stream, sse_channel};

fn delivery() -> SseDelivery {
    SseDelivery {
        transport_version: 1,
        replay_session_id: "session".into(),
        live_delivery_id: None,
        delivery_sequence: 1,
        canonical_event: serde_json::json!({"kind": "event"}),
        replay_cursor: "opaque-cursor".into(),
    }
}

fn terminal() -> SseTerminalFrame {
    SseTerminalFrame {
        transport_version: 1,
        reason: "SessionClosed".into(),
        message: "session closed".into(),
    }
}

#[tokio::test]
async fn test_sse_stream_delivers_events() {
    let (sender, receiver) = sse_channel(2);
    sender.send(SseItem::Delivery(delivery())).await.unwrap();
    sender.send(SseItem::Terminal(terminal())).await.unwrap();
    let mut body = into_sse_stream(receiver, Duration::from_secs(1))
        .into_response()
        .into_body()
        .into_data_stream();

    let frame = body.next().await.unwrap().unwrap();

    let frame = String::from_utf8(frame.to_vec()).unwrap();
    assert!(frame.contains("event: delivery"));
    assert!(frame.contains("replaySessionId"));
}

#[tokio::test]
async fn test_sse_stream_sends_heartbeats() {
    let (sender, receiver) = sse_channel(1);
    let mut body = into_sse_stream(receiver, Duration::from_millis(10))
        .into_response()
        .into_body()
        .into_data_stream();

    let frame = tokio::time::timeout(Duration::from_millis(100), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(
        String::from_utf8(frame.to_vec())
            .unwrap()
            .contains(": ping")
    );
    drop(sender);
}

#[tokio::test]
async fn test_sse_stream_terminates_on_terminal_frame() {
    let (sender, receiver) = sse_channel(1);
    sender.send(SseItem::Terminal(terminal())).await.unwrap();
    let mut body = into_sse_stream(receiver, Duration::from_secs(1))
        .into_response()
        .into_body()
        .into_data_stream();

    let frame = body.next().await.unwrap().unwrap();

    assert!(
        String::from_utf8(frame.to_vec())
            .unwrap()
            .contains("event: terminal")
    );
    assert!(body.next().await.is_none());
}

#[tokio::test]
async fn test_sse_stream_terminates_on_sender_drop() {
    let (sender, receiver) = sse_channel(1);
    drop(sender);
    let mut body = into_sse_stream(receiver, Duration::from_secs(1))
        .into_response()
        .into_body()
        .into_data_stream();

    let result = tokio::time::timeout(Duration::from_millis(100), body.next()).await;

    assert!(matches!(result, Ok(None)));
}
