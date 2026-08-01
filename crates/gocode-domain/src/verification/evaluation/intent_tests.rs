    use super::*;
fn td(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[test]
    fn reserve_succeeds() {
        let mut s = IntentStore::new();
        s.reserve(uuid::Uuid::now_v7(), "k1", td(1), td(2)).unwrap();
    }
    #[test]
    fn reserve_duplicate_returns_prior() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        assert!(s.reserve(id, "k1", td(1), td(2)).is_ok());
    }
    #[test]
    fn reserve_different_key_conflict() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        assert!(s.reserve(id, "k2", td(1), td(2)).is_err());
    }
    #[test]
    fn claim_dispatching_succeeds() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
    }
    #[test]
    fn claim_invalidated_rejected() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.invalidate(&id).unwrap();
        assert!(s.claim_dispatching(&id, &td(0)).is_err());
    }
    #[test]
    fn invalidate_reserved_works() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.invalidate(&id).unwrap();
    }
    #[test]
    fn invalidate_dispatching_noop() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.invalidate(&id).unwrap(); /* no-op */
    }
    #[test]
    fn settle_completed() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.settle(&id, true).unwrap();
    }
    #[test]
    fn reconcile_not_started() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(&id, &DispatchEvidence::NotStarted).unwrap();
    }
    #[test]
    fn reconcile_acknowledged() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(
            &id,
            &DispatchEvidence::Acknowledged {
                ack_ref: "ack1".into(),
                outcome: "success".into(),
            },
        )
        .unwrap();
    }
    #[test]
    fn reconcile_unknown_stays() {
        let mut s = IntentStore::new();
        let id = uuid::Uuid::now_v7();
        s.reserve(id, "k1", td(1), td(2)).unwrap();
        s.claim_dispatching(&id, &td(0)).unwrap();
        s.reconcile(&id, &DispatchEvidence::Unknown).unwrap();
    }
