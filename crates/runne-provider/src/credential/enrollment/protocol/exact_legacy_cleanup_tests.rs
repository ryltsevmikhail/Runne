use crate::*;
use runne_domain::id::{CommandId, IdempotencyKey};

#[test]
fn exact_legacy_cleanup_command_requires_durable_binding() {
    assert!(CredentialBrokerCommand::from_operation(&snapshot(None), attempt()).is_err());
    let binding = source_binding(1, 2, 3, 4, 5);
    let command =
        CredentialBrokerCommand::from_operation(&snapshot(Some(binding.clone())), attempt())
            .unwrap();
    assert_eq!(
        command.target(),
        &CredentialBrokerTarget::ExactLegacySource(binding)
    );
    assert!(command.target().version_ref().is_none());
}

#[test]
fn exact_legacy_cleanup_codec_roundtrip_does_not_reinterpret_old_source_tag() {
    let command = command(source_binding(1, 2, 3, 4, 5));
    let encoded = CredentialBrokerCommandCodec::encode(&command).unwrap();
    assert_eq!(
        CredentialBrokerCommandCodec::decode(&encoded).unwrap(),
        command
    );
    let old = CredentialBrokerCommand::new(
        command.operation_id(),
        attempt(),
        command.provider().clone(),
        command.action(),
        CredentialBrokerTarget::LegacySource,
        command.expected_lifecycle_revision(),
        command.expected_prior_fence(),
        None,
    )
    .unwrap();
    let old_bytes = CredentialBrokerCommandCodec::encode(&old).unwrap();
    assert_eq!(
        CredentialBrokerCommandCodec::decode(&old_bytes).unwrap(),
        old
    );
    assert_ne!(old_bytes, encoded);
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(CredentialBrokerCommandCodec::decode(&extra).is_err());
    for length in 0..encoded.len() {
        assert!(CredentialBrokerCommandCodec::decode(&encoded[..length]).is_err());
    }
}

#[test]
fn exact_legacy_cleanup_claim_rejects_every_changed_import_field() {
    let accepted = command(source_binding(1, 2, 3, 4, 5));
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([9; 32]).unwrap();
    let claim_binding = digest(10);
    for changed in [
        source_binding(6, 2, 3, 4, 5),
        source_binding(1, 6, 3, 4, 5),
        source_binding(1, 2, 6, 4, 5),
        source_binding(1, 2, 3, 6, 5),
        source_binding(1, 2, 3, 4, 6),
    ] {
        let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
        let pending = issuer.issue_pending_claim(&accepted, claim_binding, &channel);
        let authorization = issuer
            .claim_accepted(
                pending,
                CredentialBrokerFrame::ClaimAccepted {
                    operation_id: accepted.operation_id(),
                    attempt: accepted.ticket_attempt(),
                },
                &accepted,
                claim_binding,
                &channel,
            )
            .unwrap();
        assert!(
            effects
                .authorize(authorization, command(changed), claim_binding, &channel)
                .is_err()
        );
    }
}

#[test]
fn exact_legacy_cleanup_rejects_wrong_provider_and_revision_boundary() {
    let binding = source_binding(1, 2, 3, 4, 5);
    for (provider, lifecycle, fence) in [("anthropic", 3, 4), ("openai", 4, 4), ("openai", 3, 5)] {
        assert!(
            CredentialBrokerCommand::new(
                CredentialOperationId::from_bytes([8; 16]).unwrap(),
                attempt(),
                ProviderId::new(provider).unwrap(),
                CredentialOperationAction::LegacySourceCleanup,
                CredentialBrokerTarget::ExactLegacySource(binding.clone()),
                CredentialLifecycleRevision::new(lifecycle).unwrap(),
                CredentialFence::new(fence).unwrap(),
                None,
            )
            .is_err()
        );
    }
    let overflow = source_binding(1, u64::MAX, 3, 4, 5);
    assert!(
        CredentialBrokerCommand::new(
            CredentialOperationId::from_bytes([8; 16]).unwrap(),
            attempt(),
            ProviderId::new("openai").unwrap(),
            CredentialOperationAction::LegacySourceCleanup,
            CredentialBrokerTarget::ExactLegacySource(overflow),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(4).unwrap(),
            None,
        )
        .is_err()
    );
}

#[test]
fn exact_legacy_cleanup_recovery_rejects_changed_or_unbound_source() {
    let source = source_binding(1, 2, 3, 4, 5);
    let prepared = snapshot(Some(source.clone()));
    let operation = CredentialOperationSnapshot::new(
        prepared.operation_id(),
        prepared.provider().clone(),
        prepared.action(),
        CredentialOperationState::Claimed,
        None,
        None,
        prepared
            .metadata()
            .clone()
            .with_claim(digest(20), digest(21)),
    )
    .unwrap();
    let exact = command(source);
    assert!(
        CredentialRecoveryWork::new(operation.clone())
            .unwrap()
            .with_command(exact.clone())
            .is_ok()
    );
    let unbound = CredentialBrokerCommand::new(
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
    for wrong in [command(source_binding(1, 2, 3, 4, 6)), unbound] {
        assert!(
            CredentialRecoveryWork::new(operation.clone())
                .unwrap()
                .with_command(wrong)
                .is_err()
        );
    }
}

fn command(binding: CredentialLegacyCleanupBinding) -> CredentialBrokerCommand {
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        attempt(),
        binding.destination().provider().clone(),
        CredentialOperationAction::LegacySourceCleanup,
        CredentialBrokerTarget::ExactLegacySource(binding.clone()),
        CredentialLifecycleRevision::new(binding.import_lifecycle_revision().get() + 1).unwrap(),
        CredentialFence::new(binding.import_fence().get() + 1).unwrap(),
        None,
    )
    .unwrap()
}

fn source_binding(
    id: u8,
    revision: u64,
    fence: u64,
    version: u64,
    observation: u8,
) -> CredentialLegacyCleanupBinding {
    CredentialLegacyCleanupBinding::from_parts(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        CredentialVersionRef::new(ProviderId::new("openai").unwrap(), version).unwrap(),
        digest(observation),
    )
}

fn snapshot(binding: Option<CredentialLegacyCleanupBinding>) -> CredentialOperationSnapshot {
    let mut metadata = CredentialOperationMetadata::new(
        CommandId::from_bytes([8; 16]),
        IdempotencyKey::new("cleanup").unwrap(),
        CredentialInstallationOwnerId::from_bytes([9; 32]).unwrap(),
        CredentialLifecycleRevision::new(3).unwrap(),
        CredentialFence::new(4).unwrap(),
        digest(10),
        1,
        1,
    )
    .unwrap();
    if let Some(binding) = binding {
        metadata = metadata.with_legacy_cleanup_binding(binding);
    }
    CredentialOperationSnapshot::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::LegacySourceCleanup,
        CredentialOperationState::Prepared,
        None,
        None,
        metadata,
    )
    .unwrap()
}

fn attempt() -> CredentialTicketAttempt {
    CredentialTicketAttempt::new(1).unwrap()
}
fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
