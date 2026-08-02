    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_all_wire_uuids_parse() {
        let _: WireTaskRunId = VALID_UUID.parse().unwrap();
        let _: WireAttemptId = VALID_UUID.parse().unwrap();
        let _: ProtocolSessionId = VALID_UUID.parse().unwrap();
        let _: RequestId = VALID_UUID.parse().unwrap();
        let _: InvocationId = VALID_UUID.parse().unwrap();
        let _: ControlCorrelationId = VALID_UUID.parse().unwrap();
        let _: ControlIntentId = VALID_UUID.parse().unwrap();
    }

    #[test]
    fn test_wire_uuid_reject_wrong_version() {
        let v4 = "018f2e3a-7000-4000-8000-000000000000";
        assert!(v4.parse::<WireTaskRunId>().is_err());
    }

    #[test]
    fn test_nonce_display() {
        let n = Nonce::from_bytes([0xab; 16]);
        assert_eq!(n.to_string().len(), 32);
    }

    #[test]
    fn test_bounded_strings() {
        assert!(PluginId::new("my-plugin").is_ok());
        assert!(PluginId::new("").is_err());
        let too_long = "x".repeat(129);
        assert!(PluginId::new(too_long).is_err());
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(ProtocolVersion::V1_0.to_string(), "1.0");
        assert_eq!(ProtocolVersion::new(2, 1).to_string(), "2.1");
    }

    #[test]
    fn test_schema_revision() {
        let r = SchemaRevision::new(42);
        assert_eq!(r.value(), 42);
    }
