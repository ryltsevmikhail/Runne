use rusqlite::Connection;

use super::ProviderAuthorityIssueOutcome;
use super::authority_test_support::{Fixture, configured_connection};
use gocode_application::provider::ProviderAdmissionError;

#[test]
fn issuance_does_not_record_pre_effect_audit_before_the_effect_cas() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(fixture.issue(1).is_ok());
    let count: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM security_audit_pre_effect",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn effect_start_commits_exact_120_second_deadline_and_one_audit_row() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    assert_eq!(
        fixture
            .store
            .start_effect(admission.claim(), &credential)
            .unwrap()
            .expires_at(),
        1_120
    );
    let rows: (i64, i64, i64) = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT effect_started_at, effect_expires_at, state FROM provider_effect_starts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(rows, (1_000, 1_120, 1));
    let audit: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM security_audit_pre_effect",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audit, 1);
}

#[test]
fn effect_start_accepts_strictly_before_lease_expiry_and_rejects_at_or_after() {
    for (now, accepted) in [(1_599, true), (1_600, false), (1_601, false)] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let admission = match fixture.issue(1).unwrap() {
            ProviderAuthorityIssueOutcome::Winner(admission) => admission,
            ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
        };
        let (_, credential) = fixture.credential();
        fixture.clock.set(now);
        assert_eq!(
            fixture
                .store
                .start_effect(admission.claim(), &credential)
                .is_ok(),
            accepted,
            "now={now}"
        );
    }
}

#[test]
fn effect_start_is_one_shot_and_preserves_a_single_audit_row() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    assert!(
        fixture
            .store
            .start_effect(admission.claim(), &credential)
            .is_ok()
    );
    assert!(
        fixture
            .store
            .start_effect(admission.claim(), &credential)
            .is_err()
    );
    let count: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM security_audit_pre_effect",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn effect_start_returns_a_non_reconstructible_receipt_only_to_the_cas_winner() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    let receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    assert!(receipt.matches_claim(admission.claim()));
    assert!(receipt.matches_credential(&credential));
    assert!(
        fixture
            .store
            .start_effect(admission.claim(), &credential)
            .is_err()
    );
}

#[test]
fn effect_start_receipt_debug_redacts_claim_binding() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let claim = admission.claim();
    let (_, credential) = fixture.credential();
    let receipt = fixture.store.start_effect(claim, &credential).unwrap();
    let debug = format!("{receipt:?}");

    assert!(!debug.contains(&claim.provider_idempotency_key));
    assert!(!debug.contains(&format!("{:?}", claim.prepared_digest)));
    assert!(debug.contains("binding: \"<redacted>\""));
}

#[test]
fn reopening_a_started_effect_cannot_reconstruct_its_receipt() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    let receipt = fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    let reopened = super::SqliteProviderExecutionStore::open_with_connection(
        fixture.path.to_str().unwrap(),
        configured_connection(&fixture.path),
    )
    .unwrap();
    assert!(
        reopened
            .start_effect(admission.claim(), &credential)
            .is_err()
    );
    assert!(receipt.matches_claim(admission.claim()));
}

#[test]
fn concurrent_effect_start_has_exactly_one_winner() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            fixture
                .store
                .start_effect(admission.claim(), &credential)
                .is_ok()
        });
        let second = scope.spawn(|| {
            fixture
                .store
                .start_effect(admission.claim(), &credential)
                .is_ok()
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(usize::from(first) + usize::from(second), 1);
}

#[test]
fn effect_start_rejects_a_claim_with_mismatched_reservation() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let mut claim = admission.claim().clone();
    claim.token_reservation_id = [99; 16];
    let (_, credential) = fixture.credential();
    assert!(fixture.store.start_effect(&claim, &credential).is_err());
    let starts: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(starts, 0);
}

#[test]
fn committed_effect_with_lost_readback_is_reported_uncertain() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture.store.fail_next_effect_readback();
    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::PostClaimUncertain)
    );
    let rows: (i64, i64) = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_effect_starts),
                (SELECT COUNT(*) FROM security_audit_pre_effect)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rows, (1, 1));
}

#[test]
fn revoked_credential_cannot_cross_the_effect_start_cas() {
    use gocode_provider::{ProviderCredentialVersionStore, RevokeCredentialVersion};

    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (lifecycle, credential) = fixture.credential();
    lifecycle
        .revoke_and_fence(
            RevokeCredentialVersion::new(credential.version_ref().clone(), 13).unwrap(),
        )
        .unwrap();

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    let starts: i64 = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(starts, 0);
}
