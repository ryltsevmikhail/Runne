    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "aggregateId": "018f2e3a-7000-7000-8000-000000000110",
            "aggregateType": "conversation",
            "causationEventId": "018f2e3a-7000-7000-8000-000000000111",
            "correlationId": "018f2e3a-7000-7000-8000-000000000110",
            "correlationType": "conversation",
            "cursor": "runne-replay-cursor-v1.7b7d",
            "eventId": "018f2e3a-7000-7000-8000-000000000112",
            "eventType": "conversation.message.appended",
            "integrityDigest": "1111111111111111111111111111111111111111111111111111111111111111",
            "payload": {
                "attemptId": "018f2e3a-7000-7000-8000-000000000114",
                "messageId": "018f2e3a-7000-7000-8000-000000000115",
                "role": "assistant",
                "taskRunId": "018f2e3a-7000-7000-8000-000000000113",
                "text": "bounded text",
                "type": "conversation.message.appended"
            },
            "replayBindingId": "018f2e3a700070008000000000000121",
            "schemaVersion": 1,
            "sensitivity": "sensitive",
            "sequence": 2,
            "timestampUnixMicros": 1_722_330_000_000_000_i64
        })
    }

    fn validator() -> DeliveryValidator {
        DeliveryValidator::new(
            ReplayScope::new(
                ReplayAggregateKind::Conversation,
                CanonicalId::parse("018f2e3a-7000-7000-8000-000000000110").unwrap(),
            ),
            ReplayIdentityTracker::new(),
        )
    }

    fn session() -> ReplaySessionId {
        wire::session_id("018f2e3a700070008000000000000118").unwrap()
    }

    fn validate(
        validator: &mut DeliveryValidator,
        value: serde_json::Value,
    ) -> Result<ReplayDelivery, ReplayClientError> {
        let (event, cursor) = parse_http_delivery(value)?;
        validator.validate(event, cursor, session())
    }
