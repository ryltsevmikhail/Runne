use crate::{
    CredentialBrokerCommand, CredentialBrokerTarget, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, ProviderId,
};

#[test]
fn legacy_source_binding_preserves_persisted_v1_digest_bytes() {
    // Independently calculated from the pre-refactor readback transcript,
    // including the version-4 reference digest, not from the helper under test.
    let expected = [
        0xf9, 0x88, 0x5d, 0xee, 0xcb, 0x44, 0x10, 0x71, 0x49, 0xba, 0x57, 0x19, 0xdf, 0x44, 0xfd,
        0x79, 0x4b, 0xa0, 0x51, 0xb9, 0x80, 0x42, 0xc4, 0x79, 0x51, 0x32, 0x21, 0x95, 0x31, 0x5c,
        0x68, 0x16,
    ];
    assert_eq!(
        command(1, "openai", 2, 3, 4, 1)
            .legacy_source_observation_digest([7; 16])
            .unwrap()
            .as_bytes(),
        expected,
    );
}

#[test]
fn legacy_source_binding_rejects_zero_revision_and_non_import_action() {
    let import = command(1, "openai", 2, 3, 4, 1);
    assert!(import.legacy_source_observation_digest([0; 16]).is_err());
    let pair = CredentialBrokerCommand::new(
        import.operation_id(),
        import.ticket_attempt(),
        import.provider().clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(import.target().version_ref().unwrap().clone()),
        import.expected_lifecycle_revision(),
        import.expected_prior_fence(),
        None,
    )
    .unwrap();
    assert!(pair.legacy_source_observation_digest([7; 16]).is_err());
}

#[test]
fn legacy_source_binding_changes_with_every_durable_source_identity_field() {
    let baseline = command(1, "openai", 2, 3, 4, 1)
        .legacy_source_observation_digest([7; 16])
        .unwrap();
    for changed in [
        command(2, "openai", 2, 3, 4, 1),
        command(1, "anthropic", 2, 3, 4, 1),
        command(1, "openai", 5, 3, 4, 1),
        command(1, "openai", 2, 5, 4, 1),
        command(1, "openai", 2, 3, 5, 1),
    ] {
        assert_ne!(
            changed.legacy_source_observation_digest([7; 16]).unwrap(),
            baseline,
        );
    }
    assert_ne!(
        command(1, "openai", 2, 3, 4, 1)
            .legacy_source_observation_digest([8; 16])
            .unwrap(),
        baseline,
    );
    assert_eq!(
        command(1, "openai", 2, 3, 4, 2)
            .legacy_source_observation_digest([7; 16])
            .unwrap(),
        baseline,
    );
}

fn command(
    operation: u8,
    provider: &str,
    lifecycle: u64,
    fence: u64,
    version: u64,
    attempt: u64,
) -> CredentialBrokerCommand {
    let provider = ProviderId::new(provider).unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        CredentialTicketAttempt::new(attempt).unwrap(),
        provider.clone(),
        CredentialOperationAction::MigrateLegacy,
        CredentialBrokerTarget::LegacyImport(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(lifecycle).unwrap(),
        CredentialFence::new(fence).unwrap(),
        None,
    )
    .unwrap()
}
