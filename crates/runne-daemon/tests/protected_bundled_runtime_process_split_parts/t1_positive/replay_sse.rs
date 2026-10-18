use super::*;

pub(super) async fn assert_fixture_response_over_sse(
    live: &mut runne_runtime_client::ReplayLiveSession,
    scanner: &secret_scan::SecretScanner,
) {
    let mut saw_sse_response = false;
    for _ in 0..8 {
        let event = tokio::time::timeout(Duration::from_secs(5), live.next_event())
            .await
            .expect("replay SSE delivery timeout")
            .expect("replay SSE delivery");
        match event {
            runne_runtime_client::ReplayStreamEvent::Delivery(delivery) => {
                let fixture_response = match delivery.event().payload() {
                    runne_runtime_client::CanonicalReplayPayload::Conversation(
                        runne_runtime_client::ConversationReplayPayload::MessageAppended {
                            role,
                            text,
                            ..
                        },
                    ) => {
                        assert_absent("decoded replay SSE message", text.as_bytes(), scanner);
                        *role == runne_runtime_client::ConversationMessageRole::Assistant
                            && text == "fixture response"
                    }
                    _ => false,
                };
                if fixture_response {
                    saw_sse_response = true;
                }
                live.acknowledge(&delivery)
                    .await
                    .expect("acknowledge validated SSE delivery");
                if saw_sse_response {
                    break;
                }
            }
            runne_runtime_client::ReplayStreamEvent::Heartbeat => {}
            runne_runtime_client::ReplayStreamEvent::Terminal(_) => break,
        }
    }
    assert!(
        saw_sse_response,
        "assistant output must arrive over replay SSE"
    );
}
