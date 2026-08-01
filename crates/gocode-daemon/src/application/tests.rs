    use super::*;
    use gocode_api::{DaemonInstanceId, RuntimeSessionBinding};
    use gocode_domain::id::EventLogLineageId;

    fn replay_binding() -> RuntimeSessionBinding {
        let authority = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 1,
        ];
        let daemon = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 2,
        ];
        let session = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 3,
        ];
        RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                authority,
                ApiPrincipalId::new("local-owner").unwrap(),
                EventLogLineageId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 4,
                ]),
                "gocode-ui-client/1",
                [0x33; 32],
                [0x44; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes(daemon),
            7,
            session,
            3,
            Sensitivity::Internal,
            [0x77; 32],
        )
        .unwrap()
    }

    #[test]
    fn production_replay_authorization_reads_live_local_session_state() {
        let local_session = Arc::new(Mutex::new(LocalSessionService::new(
            replay_binding(),
            [0x88; 32],
        )));
        let authorization = DaemonReplayAuthorization::new([0x99; 16], Arc::clone(&local_session));
        let request = ReplayAuthorizationRequest {
            principal_id: "local-owner".to_owned(),
            authority_id: [0x99; 16],
            session_generation: 7,
            expected_epoch: 3,
            session_id: Some([0xAA; 16]),
            scope: None,
        };

        let initial = authorization.current_lease(&request).unwrap();
        assert_eq!(initial.authorization_epoch(), 3);
        assert_eq!(initial.sensitivity_ceiling(), Sensitivity::Internal);

        local_session
            .lock()
            .unwrap()
            .set_sensitivity_ceiling(Sensitivity::Public);
        let downgraded = authorization.current_lease(&request).unwrap();
        assert_eq!(downgraded.authorization_epoch(), 3);
        assert_eq!(downgraded.sensitivity_ceiling(), Sensitivity::Public);

        local_session.lock().unwrap().set_authorization_epoch(4);
        assert_eq!(
            authorization
                .current_lease(&request)
                .unwrap()
                .authorization_epoch(),
            4
        );
    }
