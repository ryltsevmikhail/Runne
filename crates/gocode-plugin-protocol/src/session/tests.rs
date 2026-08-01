    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_session_envelope_builder() {
        let sid: ProtocolSessionId = VALID_UUID.parse().unwrap();
        let tid: WireTaskRunId = VALID_UUID.parse().unwrap();
        let aid: WireAttemptId = VALID_UUID.parse().unwrap();
        let rid: RequestId = VALID_UUID.parse().unwrap();
        let iid: InvocationId = VALID_UUID.parse().unwrap();
        let pid = ProfileId::new("test-profile").unwrap();
        let hi = HostExecutionIdentity::Plugin(crate::id::PluginIdentity::new("host").unwrap());

        let envelope: SessionEnvelope<String> = SessionEnvelope::new(
            sid,
            pid.clone(),
            ProtocolVersion::V1_0,
            WireContractDigest::from_bytes([0; 32]),
            SchemaBundleDigest::from_bytes([0; 32]),
            Direction::HostToPlugin,
            1,
            MessageTypeId::new(100),
            SchemaRevision::new(1),
            hi,
            tid,
            aid,
            MessageCorrelation::Invocation {
                request_id: rid,
                invocation_id: iid,
                invocation_permit: None,
            },
            DeadlineUnixMillis::new(9999999),
            MessageDigest::from_bytes([0; 32]),
            PayloadDigest::from_bytes([0; 32]),
            ProfileDigest::from_bytes([0; 32]),
            Sensitivity::Public,
            vec![],
            "hello".to_string(),
        );

        assert_eq!(*envelope.session_id(), sid);
        assert_eq!(envelope.sequence(), 1);
        assert_eq!(envelope.into_message(), "hello");
    }

    #[test]
    fn test_message_correlation_invocation() {
        let rid: RequestId = VALID_UUID.parse().unwrap();
        let iid: InvocationId = VALID_UUID.parse().unwrap();
        let corr = MessageCorrelation::Invocation {
            request_id: rid,
            invocation_id: iid,
            invocation_permit: Some(InvocationPermitRef::new(42)),
        };
        match corr {
            MessageCorrelation::Invocation {
                request_id,
                invocation_id: _,
                invocation_permit,
            } => {
                assert_eq!(request_id, rid);
                assert_eq!(invocation_permit.unwrap().value(), 42);
            }
            _ => panic!("expected Invocation"),
        }
    }
