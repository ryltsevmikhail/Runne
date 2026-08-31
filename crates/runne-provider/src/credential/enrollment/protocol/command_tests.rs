use super::super::{
    CredentialBrokerCommand, CredentialBrokerCommandCodec, CredentialBrokerTarget, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn command_rejects_mismatched_provider_action_target_and_migration_binding() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(ProviderId::new("anthropic").unwrap(), 1).unwrap();
    assert!(
        CredentialBrokerCommand::new(
            operation(),
            attempt(),
            provider.clone(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(version),
            revision(),
            fence(),
            None,
        )
        .is_err()
    );
    assert!(
        CredentialBrokerCommand::new(
            operation(),
            attempt(),
            provider,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialBrokerTarget::Migration {
                migration_id: CredentialOperationId::from_bytes([2; 16]).unwrap(),
                phase: crate::WriterIdentityMigrationPhase::OldWriterEffect,
            },
            revision(),
            fence(),
            None,
        )
        .is_err()
    );
}

#[test]
fn command_codec_is_canonical_and_rejects_noncanonical_or_unknown_bytes() {
    let command = version_command();
    let bytes = CredentialBrokerCommandCodec::encode(&command).unwrap();
    let decoded = CredentialBrokerCommandCodec::decode(&bytes).unwrap();
    assert_eq!(
        CredentialBrokerCommandCodec::encode(&decoded).unwrap(),
        bytes
    );

    let digest = command.target().version_ref().unwrap().ref_digest();
    let offset = bytes
        .windows(digest.len())
        .position(|part| part == digest)
        .unwrap();
    let mut noncanonical = bytes;
    noncanonical[offset] ^= 1;
    for invalid in [
        noncanonical,
        vec![CredentialBrokerCommandCodec::VERSION, 0xff],
        vec![0; CredentialBrokerCommandCodec::MAX_COMMAND_BYTES + 1],
    ] {
        assert!(CredentialBrokerCommandCodec::decode(&invalid).is_err());
    }
}

#[test]
fn every_closed_action_target_shape_has_one_canonical_round_trip() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let migration = CredentialBrokerTarget::Migration {
        migration_id: CredentialOperationId::from_bytes([9; 16]).unwrap(),
        phase: crate::WriterIdentityMigrationPhase::OldWriterEffect,
    };
    let cases = [
        (
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(version.clone()),
            None,
        ),
        (
            CredentialOperationAction::Revoke,
            CredentialBrokerTarget::Version(version.clone()),
            None,
        ),
        (
            CredentialOperationAction::MigrateLegacy,
            CredentialBrokerTarget::LegacyImport(version.clone()),
            None,
        ),
        (
            CredentialOperationAction::RetiredVersionCleanup,
            CredentialBrokerTarget::Version(version),
            None,
        ),
        (
            CredentialOperationAction::LegacySourceCleanup,
            CredentialBrokerTarget::LegacySource,
            None,
        ),
        (
            CredentialOperationAction::WriterIdentityMigrationEffect,
            migration,
            Some(crate::CredentialBindingDigest::from_measured([8; 32]).unwrap()),
        ),
        (
            CredentialOperationAction::WriterIdentityMigrationVerify,
            CredentialBrokerTarget::Migration {
                migration_id: CredentialOperationId::from_bytes([9; 16]).unwrap(),
                phase: crate::WriterIdentityMigrationPhase::NewWriterVerify,
            },
            Some(crate::CredentialBindingDigest::from_measured([8; 32]).unwrap()),
        ),
    ];

    for (action, target, binding) in cases {
        let command = CredentialBrokerCommand::new(
            operation(),
            attempt(),
            provider.clone(),
            action,
            target,
            revision(),
            fence(),
            binding,
        )
        .unwrap();
        let encoded = CredentialBrokerCommandCodec::encode(&command).unwrap();
        assert_eq!(
            CredentialBrokerCommandCodec::decode(&encoded).unwrap(),
            command
        );
    }
}

fn version_command() -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        operation(),
        attempt(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        revision(),
        fence(),
        None,
    )
    .unwrap()
}

fn operation() -> CredentialOperationId {
    CredentialOperationId::from_bytes([1; 16]).unwrap()
}
fn attempt() -> CredentialTicketAttempt {
    CredentialTicketAttempt::new(1).unwrap()
}
fn revision() -> CredentialLifecycleRevision {
    CredentialLifecycleRevision::new(1).unwrap()
}
fn fence() -> CredentialFence {
    CredentialFence::new(1).unwrap()
}
