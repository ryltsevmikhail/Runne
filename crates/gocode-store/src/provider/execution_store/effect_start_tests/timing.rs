use std::time::Duration;

use super::{Connection, Fixture, ProviderAdmissionError, ProviderAuthorityIssueOutcome};

#[test]
fn effect_start_samples_expiry_only_after_waiting_for_the_write_lock() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture.clock.set(1_599);
    let reads_before = fixture.clock.read_count();
    let blocker = Connection::open(&fixture.path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let (sampled_while_locked, result) = std::thread::scope(|scope| {
        let pending = scope.spawn(|| fixture.store.start_effect(admission.claim(), &credential));
        let mut sampled = false;
        for _ in 0..100 {
            if fixture.clock.read_count() > reads_before {
                sampled = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        fixture.clock.set(1_600);
        blocker.execute_batch("COMMIT").unwrap();
        (sampled, pending.join().unwrap())
    });

    assert_eq!(
        result,
        Err(ProviderAdmissionError::AuthorityDenied),
        "clock sampled before acquired transaction: {sampled_while_locked}"
    );
    assert_eq!(effect_start_count(&fixture), 0);
}

#[test]
fn effect_start_rejects_provider_clock_rollback() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture.clock.set(999);

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(effect_start_count(&fixture), 0);
}

#[test]
fn effect_start_rechecks_lease_expiry_at_the_durable_boundary() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture.clock.set(1_599);
    fixture
        .clock
        .step_on_read(fixture.clock.read_count() + 2, 1_600);

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(effect_start_count(&fixture), 0);
}

#[test]
fn effect_start_withholds_receipt_when_lease_expires_before_readback() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture.clock.set(1_599);
    fixture
        .clock
        .step_on_read(fixture.clock.read_count() + 3, 1_600);

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(effect_start_count(&fixture), 1);
}

#[test]
fn effect_start_withholds_receipt_on_post_commit_clock_rollback() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let (_, credential) = fixture.credential();
    fixture
        .clock
        .step_on_read(fixture.clock.read_count() + 3, 999);

    assert_eq!(
        fixture.store.start_effect(admission.claim(), &credential),
        Err(ProviderAdmissionError::PostClaimUncertain)
    );
    assert_eq!(effect_start_count(&fixture), 1);
}

fn effect_start_count(fixture: &Fixture) -> i64 {
    Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap()
}
