use crate::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec, CredentialSecretOfferCodec,
    CredentialTicketAttempt, CredentialVersionRef, ProviderId, WriterIdentityMigrationPhase,
};
use zeroize::Zeroizing;

use super::super::publication::CredentialSecretPublicationVerifier;
use super::binding;

#[test]
fn secret_offer_rejects_every_non_pair_action() {
    for (offset, action, target, migration_binding) in [
        (
            41,
            CredentialOperationAction::Revoke,
            CredentialBrokerTarget::Version(version()),
            None,
        ),
        (
            42,
            CredentialOperationAction::MigrateLegacy,
            CredentialBrokerTarget::LegacyImport(version()),
            None,
        ),
        (
            43,
            CredentialOperationAction::RetiredVersionCleanup,
            CredentialBrokerTarget::Version(version()),
            None,
        ),
        (
            44,
            CredentialOperationAction::LegacySourceCleanup,
            CredentialBrokerTarget::LegacySource,
            None,
        ),
        (
            45,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            migration_target(WriterIdentityMigrationPhase::OldWriterEffect),
            Some(binding(45)),
        ),
        (
            46,
            CredentialOperationAction::WriterIdentityMigrationVerify,
            migration_target(WriterIdentityMigrationPhase::NewWriterVerify),
            Some(binding(46)),
        ),
    ] {
        let command = command(offset, action, target, migration_binding);
        assert!(CredentialSecretClaimOffer::prepare(&command, binding(47)).is_err());
    }
}

#[test]
fn secret_offer_rejects_each_non_version_target_variant() {
    for (offset, action, target, migration_binding) in [
        (
            48,
            CredentialOperationAction::MigrateLegacy,
            CredentialBrokerTarget::LegacyImport(version()),
            None,
        ),
        (
            49,
            CredentialOperationAction::LegacySourceCleanup,
            CredentialBrokerTarget::LegacySource,
            None,
        ),
        (
            50,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            migration_target(WriterIdentityMigrationPhase::OldWriterEffect),
            Some(binding(50)),
        ),
    ] {
        let command = command(offset, action, target, migration_binding);
        assert!(CredentialSecretClaimOffer::prepare(&command, binding(51)).is_err());
    }
}

#[test]
fn secret_offer_writer_key_is_fresh_per_prepare() {
    let command = command(
        53,
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(version()),
        None,
    );
    let (first, _) = CredentialSecretClaimOffer::prepare(&command, binding(54)).unwrap();
    let (second, _) = CredentialSecretClaimOffer::prepare(&command, binding(54)).unwrap();

    assert_ne!(
        CredentialSecretOfferCodec::encode(&first),
        CredentialSecretOfferCodec::encode(&second)
    );
}

#[test]
fn secret_envelope_sealer_key_is_fresh_for_one_writer_key() {
    let command = command(
        55,
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(version()),
        None,
    );
    let (offer, _) = CredentialSecretClaimOffer::prepare(&command, binding(56)).unwrap();
    let offer_bytes = CredentialSecretOfferCodec::encode(&offer);
    let channel = super::channel();
    let first_offer = CredentialSecretOfferCodec::decode(&offer_bytes).unwrap();
    let (daemon, publication) =
        super::super::publication::fixture_publication(&first_offer, &channel);
    let first = CredentialSecretPublicationVerifier::new(daemon, &channel)
        .verify(first_offer, publication)
        .unwrap()
        .seal(Zeroizing::new(b"credential".to_vec()))
        .unwrap();
    let second_offer = CredentialSecretOfferCodec::decode(&offer_bytes).unwrap();
    let (_, publication) = super::super::publication::fixture_publication(&second_offer, &channel);
    let second = CredentialSecretPublicationVerifier::new(daemon, &channel)
        .verify(second_offer, publication)
        .unwrap()
        .seal(Zeroizing::new(b"credential".to_vec()))
        .unwrap();

    assert_ne!(
        CredentialSecretEnvelopeCodec::encode(&first).unwrap(),
        CredentialSecretEnvelopeCodec::encode(&second).unwrap()
    );
}

fn command(
    id: u8,
    action: CredentialOperationAction,
    target: CredentialBrokerTarget,
    migration_binding: Option<CredentialBindingDigest>,
) -> CredentialBrokerCommand {
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider(),
        action,
        target,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        migration_binding,
    )
    .unwrap()
}

fn migration_target(phase: WriterIdentityMigrationPhase) -> CredentialBrokerTarget {
    CredentialBrokerTarget::Migration {
        migration_id: CredentialOperationId::from_bytes([52; 16]).unwrap(),
        phase,
    }
}

fn version() -> CredentialVersionRef {
    CredentialVersionRef::new(provider(), 1).unwrap()
}

fn provider() -> ProviderId {
    ProviderId::new("openai").unwrap()
}
