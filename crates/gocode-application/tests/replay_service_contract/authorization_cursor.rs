#[tokio::test]
async fn public_constructor_requires_and_uses_independent_authorization() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        Arc::new(DenyAuthorization),
    );

    let error = service
        .open_session("user", 1, &[5; 16], 0, 1, &[2; 16], None, delivery_guard())
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
}

#[test]
fn cursor_integrity_rejects_tampering() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        lineage,
        allow_authorization(),
    );
    let event = event();
    let scope = scope();
    let mut cursor = service.build_cursor_from_event(&event, &scope).unwrap();
    cursor.global_position = 43;
    let result = futures::executor::block_on(service.open_session(
        "user",
        1,
        &[5; 16],
        0,
        1,
        &[2; 16],
        Some(cursor),
        delivery_guard(),
    ));
    assert!(matches!(result, Err(ReplayError::CursorInvalid { .. })));
}

#[test]
fn cursor_construction_is_deterministic() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
    );
    let event = event();
    let scope = scope();

    assert_eq!(
        service.build_cursor_from_event(&event, &scope).unwrap(),
        service.build_cursor_from_event(&event, &scope).unwrap(),
    );
}

#[test]
fn cursor_construction_rejects_invalid_delivered_event_metadata() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
    );
    let mut invalid = event();
    invalid.sequence = 0;

    assert!(matches!(
        service.build_cursor_from_event(&invalid, &scope()),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn cursor_integrity_accepts_valid_cursor() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
    );
    let cursor = service.build_cursor_from_event(&event(), &scope()).unwrap();

    assert!(service.validate_cursor_integrity(&cursor).is_ok());
}

#[test]
fn cursor_rejects_wrong_server_secret() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let issuing_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        lineage,
        allow_authorization(),
    );
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xDD; 32],
        lineage,
        allow_authorization(),
    );

    assert!(matches!(
        validating_service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}

#[test]
fn cursor_rejects_wrong_schema_version() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
    );
    let mut cursor = service.build_cursor_from_event(&event(), &scope()).unwrap();
    cursor.schema_version = CURSOR_SCHEMA_VERSION + 1;

    assert!(matches!(
        service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}

#[test]
fn cursor_rejects_foreign_event_log_lineage() {
    let issuing_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
    );
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([5; 16]),
        allow_authorization(),
    );

    assert!(matches!(
        validating_service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}
