use super::ProviderCredentialSourceRevision;
use runne_provider::*;

#[test]
fn source_cleanup_rejects_misplaced_and_uncommitted_slots() {
    use super::source_update::{
        ProviderCredentialSourceSlot::{Alternate, Primary},
        ProviderCredentialSourceSlotState::{Committed, Pending},
        ProviderCredentialSourceSlotVersion as Version,
    };
    for (physical, recorded, valid) in [
        (Primary, None, true),
        (Alternate, None, false),
        (
            Primary,
            Some(Version::new(Primary, 1, Committed).unwrap()),
            true,
        ),
        (
            Alternate,
            Some(Version::new(Alternate, 2, Committed).unwrap()),
            true,
        ),
        (
            Primary,
            Some(Version::new(Alternate, 2, Committed).unwrap()),
            false,
        ),
        (
            Alternate,
            Some(Version::new(Primary, 1, Committed).unwrap()),
            false,
        ),
        (
            Primary,
            Some(Version::new(Primary, 1, Pending).unwrap()),
            false,
        ),
        (
            Alternate,
            Some(Version::new(Alternate, 2, Pending).unwrap()),
            false,
        ),
    ] {
        assert_eq!(
            super::source_cleanup::validate_slot(physical, recorded).is_ok(),
            valid
        );
    }
}

#[test]
fn source_cleanup_selects_only_the_imported_revision() {
    let binding = binding();
    let source = ProviderCredentialSourceRevision::new([7; 16]).unwrap();
    assert_eq!(
        super::source_cleanup::select(&binding, vec![(source, 41)]).unwrap(),
        Some(41)
    );
    let replacement = ProviderCredentialSourceRevision::new([8; 16]).unwrap();
    assert!(super::source_cleanup::select(&binding, vec![(replacement, 42)]).is_err());
}

#[test]
fn source_cleanup_rejects_ambiguity_without_selecting_any_item() {
    let source = ProviderCredentialSourceRevision::new([7; 16]).unwrap();
    assert!(super::source_cleanup::select(&binding(), vec![(source, 41), (source, 42)]).is_err());
    assert_eq!(
        super::source_cleanup::select::<u8>(&binding(), vec![]).unwrap(),
        None
    );
}

pub(super) fn binding() -> CredentialLegacyCleanupBinding {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let id = CredentialOperationId::from_bytes([3; 16]).unwrap();
    let lifecycle = CredentialLifecycleRevision::new(1).unwrap();
    let fence = CredentialFence::new(1).unwrap();
    let import = CredentialBrokerCommand::new(
        id,
        CredentialTicketAttempt::new(1).unwrap(),
        provider,
        CredentialOperationAction::MigrateLegacy,
        CredentialBrokerTarget::LegacyImport(version.clone()),
        lifecycle,
        fence,
        None,
    )
    .unwrap();
    CredentialLegacyCleanupBinding::from_parts(
        id,
        lifecycle,
        fence,
        version,
        import.legacy_source_observation_digest([7; 16]).unwrap(),
    )
}
