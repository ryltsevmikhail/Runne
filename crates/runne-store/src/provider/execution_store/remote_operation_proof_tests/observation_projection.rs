use runne_application::ports::RuntimeAuthorityId;
use runne_application::provider::{
    ProviderRemoteAttemptBinding, ProviderRemoteObservationProjection,
};
use rusqlite::TransactionBehavior;

pub(super) fn effects_observation_at(
    store: &crate::provider::SqliteProviderExecutionStore,
    binding: &ProviderRemoteAttemptBinding,
    now: i64,
) -> ProviderRemoteObservationProjection {
    let mut connection = store.connection.lock().unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .unwrap();
    let snapshot = super::super::load_remote_effects_snapshot_at(
        &transaction,
        &RuntimeAuthorityId("01010101010101010101010101010101".into()),
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        None,
        runne_api::SuccessorEligibilityV1::Blocked,
        now,
    )
    .unwrap()
    .unwrap();
    transaction.commit().unwrap();
    snapshot.observation
}
