    use super::*;
    use gocode_api::{
        ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding,
    };
    use gocode_application::local_session::AuthenticatedRuntimeSession;
    use gocode_application::replay_service::{
        ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayState,
    };
    use gocode_domain::event::Sensitivity;
    use gocode_domain::id::{EventLogLineageId, IntegrityDigest};
    use gocode_domain::replay::GapRangeRef;
    use gocode_store::replay_store::ReplayStore;

    struct AvailableReplayAuthorization;

    fn uuid_v7(last: u8) -> [u8; 16] {
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, last,
        ]
    }

    fn authenticated_runtime_session(session: &ReplaySession) -> AuthenticatedRuntimeSession {
        AuthenticatedRuntimeSession {
            binding: RuntimeSessionBinding::new(
                StableRuntimeBinding::new(
                    uuid_v7(1),
                    ApiPrincipalId::new(session.principal_id.clone()).unwrap(),
                    EventLogLineageId::from_bytes(uuid_v7(2)),
                    "gocode-ui-client/1",
                    [3; 32],
                    [4; 32],
                )
                .unwrap(),
                DaemonInstanceId::from_bytes(uuid_v7(5)),
                u64::try_from(session.session_generation).unwrap(),
                uuid_v7(6),
                u64::try_from(session.authorization_epoch).unwrap(),
                Sensitivity::Sensitive,
                [7; 32],
            )
            .unwrap(),
            expires_at_monotonic: Duration::from_secs(600),
        }
    }

    impl ReplayAuthorizationPort for AvailableReplayAuthorization {
        fn current_lease(
            &self,
            request: &ReplayAuthorizationRequest,
        ) -> Result<ReplayAuthorizationLease, ReplayError> {
            ReplayAuthorizationLease::new(
                request.principal_id.clone(),
                request.expected_epoch,
                Sensitivity::Sensitive,
            )
        }
    }

    #[test]
    fn page_claim_is_exclusive_and_released_on_drop() {
        let sessions = Arc::new(Mutex::new(HashSet::new()));
        let session_id = [0x42; 16];

        let first = SessionClaim::acquire(Arc::clone(&sessions), session_id).unwrap();
        assert!(SessionClaim::acquire(Arc::clone(&sessions), session_id).is_none());
        drop(first);
        assert!(SessionClaim::acquire(sessions, session_id).is_some());
    }

    #[test]
    fn replay_failures_map_to_the_closed_public_codes() {
        let retention_gap = ReplayError::ReplayRetentionGap {
            floor_cursor: None,
            gap_range_ref: GapRangeRef::new(IntegrityDigest::from_bytes([9; 32])).unwrap(),
        };
        for (error, code) in [
            (ReplayError::StaleGeneration, "replay_session_expired"),
            (
                ReplayError::AuthorizationRevoked,
                "replay_authorization_revoked",
            ),
            (ReplayError::SensitivityDenied, "replay_sensitivity_denied"),
            (
                ReplayError::Integrity("unsupported replay schema".to_owned()),
                "replay_unsupported_schema",
            ),
            (retention_gap, "replay_retention_gap"),
            (ReplayError::BackpressureExceeded, "replay_backpressure"),
            (
                ReplayError::Integrity("invalid stored digest".to_owned()),
                "runtime_invariant_violation",
            ),
        ] {
            assert_eq!(replay_error_to_http(&error).code, code);
        }
    }

    #[test]
    fn oversized_serialized_page_is_rejected_before_response_creation() {
        let error =
            bounded_json_response(StatusCode::OK, &"x".repeat(MAX_ENCODED_REPLAY_PAGE_BYTES))
                .unwrap_err();

        assert_eq!(error.code, "replay_backpressure");
    }

    #[test]
    fn maximum_canonical_failure_payload_fits_sse_frame_limit() {
        let service = ReplayService::new(
            Arc::new(ReplayStore::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
            [0x11; 32],
            EventLogLineageId::from_bytes([0x22; 16]),
            Arc::new(AvailableReplayAuthorization),
        );
        let session = ReplaySession {
            session_id: uuid_v7(0x33),
            principal_id: "principal".to_owned(),
            session_generation: i64::MAX,
            authority_id: uuid_v7(0x44),
            authorization_epoch: i64::MAX,
            aggregate_type: 1,
            aggregate_id: uuid_v7(0x55),
            retained_floor: Some(1),
            retention_generation: 0,
            high_water_position: i64::MAX,
            next_page_position: None,
            last_delivered_position: Some(i64::MAX),
            last_acked_position: Some(i64::MAX),
            state: ReplayState::Live,
            high_water_ref: vec![0x66; 32],
            catch_up_completion: None,
            live_delivery_id: Some(uuid_v7(0x77).to_vec()),
            created_at: "9999-12-31T23:59:59.999999Z".to_owned(),
        };
        let event = ReplayEvent {
            global_position: i64::MAX,
            event_id: uuid_v7(0x88),
            aggregate_type: 1,
            aggregate_id: session.aggregate_id,
            payload: TaskRunEventCodec
                .encode(&gocode_domain::task_run::TaskRunEvent::TaskRunFailed {
                    reason: "x".repeat(gocode_api::MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES),
                })
                .unwrap(),
            timestamp: i64::MIN,
            event_type: "e".repeat(256),
            sequence: i64::MAX,
            sensitivity: 0,
            schema_version: 1,
            causation_id: Some(uuid_v7(0x99)),
            command_id: uuid_v7(0xaa),
            idempotency_key: "i".repeat(256),
            actor: "a".repeat(256),
            integrity_digest: [0xbb; 32],
            correlation_id: session.aggregate_id,
            correlation_type: 1,
            integrity_profile: 1,
        };
        let authenticated = authenticated_runtime_session(&session);
        let delivery = live_delivery(&authenticated, &service, &session, &event, u64::MAX).unwrap();

        let encoded_reason_bytes = delivery.canonical_event["payload"]["reason"]
            .as_str()
            .unwrap()
            .len();
        let encoded = serde_json::to_vec(&delivery).unwrap();

        assert_eq!(
            encoded_reason_bytes,
            gocode_api::MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES
        );
        assert!(
            encoded.len() <= MAX_SSE_FRAME_BYTES,
            "actual frame={} declared={MAX_SSE_FRAME_BYTES}",
            encoded.len()
        );
    }
