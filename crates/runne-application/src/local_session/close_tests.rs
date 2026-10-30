use super::*;

#[test]
fn close_session_revokes_issuer_without_changing_other_sessions_or_limits() {
    let binding = test_binding([5; 16]);
    let mut service = LocalSessionService::new(binding.clone(), TEST_SECRET);
    let issuer = authenticate_issuer(&mut service, &binding);
    // A distinct authority remains live, even when the binding is the same.
    let session = service.sessions.get(&TEST_AUTHORITY).unwrap().clone();
    let mut other = session;
    other.authority = RuntimeSessionAuthority(Zeroizing::new([0x99; 32]));
    other.issuer_state = Arc::new(ReplayBaselineIssuerState {
        revoked: AtomicBool::new(false),
    });
    service.sessions.insert([0x99; 32], other);
    assert_eq!(
        service.close_session(&[0x77; 32], Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    );
    assert_eq!(service.sessions.len(), 2);
    service
        .close_session(&TEST_AUTHORITY, Duration::ZERO)
        .unwrap();
    assert!(issuer.state.revoked.load(Ordering::Acquire));
    assert!(
        service
            .authorize_wire(&TEST_AUTHORITY, Duration::ZERO)
            .is_err()
    );
    assert!(service.authorize_wire(&[0x99; 32], Duration::ZERO).is_ok());
    assert_eq!(
        service.close_session(&TEST_AUTHORITY, Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    );
    assert_eq!(service.sessions.len(), 1);
}
