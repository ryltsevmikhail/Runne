use runne_application::provider::ProviderExecutionStore;
use rusqlite::Connection;

use super::{Fixture, ProviderAuthorityIssueOutcome};

#[test]
fn terminal_pricing_binding_uses_the_durable_effect_start_timestamp() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let admission = match fixture.issue(1).unwrap() {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new admission"),
    };
    let attempt_id = admission.claim().attempt_id;
    let (_, credential) = fixture.credential();
    fixture
        .store
        .start_effect(admission.claim(), &credential)
        .unwrap();
    Connection::open(&fixture.path)
        .unwrap()
        .execute(
            "UPDATE provider_dispatch_attempts SET state=3, stream_id=zeroblob(16)
             WHERE attempt_id=?1",
            [attempt_id.as_bytes().as_slice()],
        )
        .unwrap();

    let binding = fixture
        .store
        .load_terminal_pricing_binding(attempt_id)
        .unwrap();
    assert_eq!(binding.effect_started_at(), 1_000);
}
