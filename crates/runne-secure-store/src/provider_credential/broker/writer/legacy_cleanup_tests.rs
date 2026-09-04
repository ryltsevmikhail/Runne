use super::*;

#[test]
fn retained_cleanup_authority_reaches_native_delete_once() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let channel = channel();
    let binding = binding(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(Arc::new(AtomicUsize::new(0)), deletes.clone()),
        access.policy.clone(),
        effects.legacy_read_verifier(binding, &channel),
    );
    let command = command(CredentialOperationAction::LegacySourceCleanup);
    let authorization = authorization(&issuer, &command, binding, &channel);
    let input = BrokeredLegacySourceDeleteInput::new(command, binding, channel).unwrap();
    source.delete_exact(&effects, authorization, input).unwrap();
    drop(access);
    assert_eq!(deletes.load(Ordering::SeqCst), 1);
}

pub(super) fn command(action: CredentialOperationAction) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    let (target, revision) = match action {
        CredentialOperationAction::MigrateLegacy => (
            CredentialBrokerTarget::LegacyImport(
                CredentialVersionRef::new(provider.clone(), 1).unwrap(),
            ),
            1,
        ),
        CredentialOperationAction::LegacySourceCleanup => (
            CredentialBrokerTarget::ExactLegacySource(
                crate::provider_credential::source_cleanup_tests::binding(),
            ),
            2,
        ),
        _ => unreachable!(),
    };
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([3; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider,
        action,
        target,
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(revision).unwrap(),
        None,
    )
    .unwrap()
}

#[test]
fn cleanup_preserves_a_replaced_source_after_matching_claim() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let channel = channel();
    let binding = binding(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore {
            loads: Arc::new(AtomicUsize::new(0)),
            deletes: deletes.clone(),
            revision: [8; 16],
        },
        access.policy.clone(),
        effects.legacy_read_verifier(binding, &channel),
    );
    let command = command(CredentialOperationAction::LegacySourceCleanup);
    let authorization = authorization(&issuer, &command, binding, &channel);
    let input = BrokeredLegacySourceDeleteInput::new(command, binding, channel).unwrap();
    assert_eq!(
        source.delete_exact(&effects, authorization, input),
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    );
    drop(access);
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

#[test]
fn cleanup_input_rejects_old_provider_scoped_target() {
    let exact = command(CredentialOperationAction::LegacySourceCleanup);
    let old = CredentialBrokerCommand::new(
        exact.operation_id(),
        exact.ticket_attempt(),
        exact.provider().clone(),
        exact.action(),
        CredentialBrokerTarget::LegacySource,
        exact.expected_lifecycle_revision(),
        exact.expected_prior_fence(),
        None,
    )
    .unwrap();
    assert!(BrokeredLegacySourceDeleteInput::new(old, binding(9), channel()).is_err());
}
