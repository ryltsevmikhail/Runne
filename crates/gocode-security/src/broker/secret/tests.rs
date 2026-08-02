    use super::*;

    #[test]
    fn resolve_requires_authorization() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        assert!(matches!(
            broker.resolve(&secret_ref, false),
            Err(SecretError::Unauthorized)
        ));
    }

    #[test]
    fn authorized_resolve_works() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        let handle = broker.resolve(&secret_ref, true).unwrap();
        assert!(handle.is_valid());
        assert_eq!(handle.value().unwrap(), b"sk-abc123");
    }

    #[test]
    fn revoked_secret_rejected() {
        let mut broker = SecretBroker::new();
        let secret_ref = broker.register("api_key", b"sk-abc123".to_vec()).unwrap();
        broker.revoke(&secret_ref).unwrap();
        assert!(matches!(
            broker.resolve(&secret_ref, true),
            Err(SecretError::ReferenceRevoked)
        ));
    }
