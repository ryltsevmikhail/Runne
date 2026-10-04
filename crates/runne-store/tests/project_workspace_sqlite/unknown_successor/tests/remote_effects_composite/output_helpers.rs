use super::support::{Prepared, commit, prepare};
use runne_application::ports::{EventStore, RuntimeAuthorityId};
use runne_application::provider::{
    ProviderRemoteAccountingProjection, ProviderRemoteLocalDisposition, ProviderRemoteRecoveryStore,
};
use runne_provider::{ProviderRemoteResponseStatus, ProviderUsage};
use runne_runtime::provider_execution::ProviderRemoteTerminalSourceOutcome;
use std::sync::Arc;

pub(super) const OUTPUT: &str = "exact authenticated provider output";

pub(super) fn completed_output_fixture(name: &str, tail: u8) -> Prepared {
    let prepared = prepare(
        name,
        tail,
        &format!("resp_{name}"),
        ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some(OUTPUT),
    );
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    prepared
}

pub(super) fn assert_pending_output(
    prepared: &Prepared,
    snapshot: &runne_application::ports::TaskRunEffectsReadSnapshot,
) {
    assert_eq!(snapshot.effects.taskrun_id, prepared.fixture.taskrun_id);
    assert_eq!(snapshot.effects.stream_version, prepared.fixture.version);
    assert_eq!(
        snapshot.effects.attempt_id,
        Some(prepared.fixture.claim_identity.attempt_id)
    );
    let remote = snapshot.remote.as_ref().expect("authenticated source");
    assert_eq!(remote.binding, expected_binding(prepared));
    assert_eq!(
        remote.local_disposition,
        ProviderRemoteLocalDisposition::Pending
    );
    assert_eq!(
        remote.fact.as_ref().unwrap().status(),
        &ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        }
    );
    assert!(remote.fact.as_ref().unwrap().output_digest().is_some());
    assert_eq!(
        remote.accounting,
        ProviderRemoteAccountingProjection::Known {
            input_tokens: 3,
            output_tokens: 4,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
            charge_micros: 10,
            currency: "USD".into(),
        }
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Withheld
    );
    assert_eq!(
        remote.fact.as_ref().unwrap().publication_disposition(),
        runne_provider::ProviderRemotePublicationDisposition::Allowed,
        "remote policy permits publication; local output is still pending"
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
}

pub(super) fn assert_output_applied(
    prepared: &Prepared,
    snapshot: &runne_application::ports::TaskRunEffectsReadSnapshot,
) {
    assert_eq!(snapshot.effects.taskrun_id, prepared.fixture.taskrun_id);
    assert_eq!(
        snapshot.effects.stream_version,
        prepared.fixture.version + 1
    );
    assert_eq!(
        snapshot.effects.attempt_id,
        Some(prepared.fixture.claim_identity.attempt_id)
    );
    let remote = snapshot.remote.as_ref().expect("authenticated source");
    assert_eq!(remote.binding, expected_binding(prepared));
    assert_eq!(
        remote.local_disposition,
        ProviderRemoteLocalDisposition::OutputApplied
    );
    assert_eq!(
        remote.fact.as_ref().unwrap().status(),
        &ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        }
    );
    assert_eq!(
        remote.fact.as_ref().unwrap().publication_disposition(),
        runne_provider::ProviderRemotePublicationDisposition::Allowed
    );
    assert_eq!(
        remote.accounting,
        ProviderRemoteAccountingProjection::Known {
            input_tokens: 3,
            output_tokens: 4,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
            charge_micros: 10,
            currency: "USD".into(),
        }
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Allowed
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
}

pub(super) fn expected_binding(
    prepared: &Prepared,
) -> runne_application::provider::ProviderRemoteAttemptBinding {
    prepared
        .fixture
        .execution
        .load_remote_attempt(prepared.attempt)
        .unwrap()
        .unwrap()
        .request
        .binding
}

pub(super) fn read_after_reopen(
    prepared: &Prepared,
) -> runne_application::ports::TaskRunEffectsReadSnapshot {
    let authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let store = crate::validated_reopen::reopen_store(
        prepared.fixture.database.file.path(),
        prepared.fixture.database.identity,
        authority,
        super::super::guard(),
    )
    .unwrap();
    let execution = Arc::new(
        crate::validated_reopen::open_provider_execution(
            prepared.fixture.database.file.path(),
            prepared.fixture.database.identity,
        )
        .unwrap(),
    );
    let committer = runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(super::super::super::effect::Keyring),
        execution,
    );
    store
        .load_task_run_effects_with_remote_authenticator(
            prepared.fixture.taskrun_id,
            Some(&committer),
            Some(&super::super::Resolver),
        )
        .unwrap()
}
