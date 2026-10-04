use super::*;

#[test]
fn successful_legacy_final_send_authority_is_one_use() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let (_, credential) = fixture.credential();
    let mut receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();

    receipt
        .take_final_send_authority()
        .unwrap()
        .consume()
        .unwrap();
    assert!(receipt.take_final_send_authority().is_err());
}

#[test]
fn legacy_final_send_rejects_runtime_revision_advance_after_readback() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(2).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let (_, credential) = fixture.credential();
    let mut receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    Connection::open(&fixture.path)
        .unwrap()
        .execute(
            "UPDATE provider_runtime_authority_state SET state_revision=state_revision+1 WHERE id=1",
            [],
        )
        .unwrap();

    let sends = std::sync::atomic::AtomicUsize::new(0);
    let result = receipt.take_final_send_authority().unwrap().consume();
    if result.is_ok() {
        sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    assert!(result.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn legacy_final_send_rejects_clock_rollback_after_readback() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(3).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let (_, credential) = fixture.credential();
    let mut receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    fixture.clock.set(999);

    let sends = std::sync::atomic::AtomicUsize::new(0);
    let result = receipt.take_final_send_authority().unwrap().consume();
    if result.is_ok() {
        sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    assert!(result.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn legacy_final_send_rejects_changed_persisted_credential_binding() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(4).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let (_, credential) = fixture.credential();
    let mut receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    Connection::open(&fixture.path)
        .unwrap()
        .execute(
            "UPDATE provider_credential_effect_bindings SET lease_owner=zeroblob(16)",
            [],
        )
        .unwrap();

    let sends = std::sync::atomic::AtomicUsize::new(0);
    let result = receipt.take_final_send_authority().unwrap().consume();
    if result.is_ok() {
        sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    assert!(result.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
}
