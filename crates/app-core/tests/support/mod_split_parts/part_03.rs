fn broadcast(
    senders: &mut Vec<(mpsc::UnboundedSender<Bytes>, u64)>,
    event: &Value,
    _event_sequence: u64,
) {
    let cursor = event_cursor(event);
    senders.retain_mut(|(sender, delivery_sequence)| {
        let envelope = json!({
            "transportVersion": 1,
            "replaySessionId": SESSION_ID,
            "liveDeliveryId": LIVE_DELIVERY_ID,
            "deliverySequence": *delivery_sequence,
            "canonicalEvent": event,
            "replayCursor": cursor
        });
        let frame = Bytes::from(format!(
            "event: delivery\ndata: {}\n\n",
            serde_json::to_string(&envelope).expect("SSE JSON")
        ));
        let sent = sender.send(frame).is_ok();
        if sent {
            *delivery_sequence += 1;
        }
        sent
    });
}
