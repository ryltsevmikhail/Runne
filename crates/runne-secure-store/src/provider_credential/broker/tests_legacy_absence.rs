use runne_provider::*;

#[test]
fn legacy_reader_rejects_version_operations_before_native_access() {
    use super::{
        ExactAbsenceReadback, ExactVersionReadback, NativeLegacySourceReadback,
        ProviderCredentialReadback,
    };
    let executable = std::env::current_exe().unwrap();
    let access = crate::ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap();
    let reader = NativeLegacySourceReadback::new(access);
    let provider = ProviderId::new("openai").unwrap();
    for action in [
        CredentialOperationAction::Pair,
        CredentialOperationAction::Revoke,
    ] {
        let command = CredentialBrokerCommand::new(
            CredentialOperationId::from_bytes([8; 16]).unwrap(),
            CredentialTicketAttempt::new(1).unwrap(),
            provider.clone(),
            action,
            CredentialBrokerTarget::Version(
                CredentialVersionRef::new(provider.clone(), 1).unwrap(),
            ),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap();
        let result = if action == CredentialOperationAction::Pair {
            reader.readback_exact_version(ExactVersionReadback::new(command).unwrap())
        } else {
            reader.readback_exact_absence(ExactAbsenceReadback::new(command).unwrap())
        };
        assert!(matches!(
            result,
            Err(crate::SecureStoreError::UnsupportedSecureStoreBackend)
        ));
    }
}

#[test]
fn legacy_inventory_requires_all_slots_absent_and_propagates_errors() {
    use crate::SecureStoreError;
    let mut visited = Vec::new();
    assert!(
        !super::legacy_presence::inspect(|slot| {
            visited.push(slot);
            Ok(false)
        })
        .unwrap()
    );
    assert_eq!(visited, [0, 1, 2]);
    for occupied in 0..3 {
        assert!(super::legacy_presence::inspect(|slot| Ok(slot == occupied)).unwrap());
    }
    assert_eq!(
        super::legacy_presence::inspect(|slot| {
            if slot == 2 {
                Err(SecureStoreError::CredentialAccessDenied)
            } else {
                Ok(false)
            }
        }),
        Err(SecureStoreError::CredentialAccessDenied)
    );
}

fn command(target: CredentialBrokerTarget, attempt: u64) -> CredentialBrokerCommand {
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([11; 16]).unwrap(),
        CredentialTicketAttempt::new(attempt).unwrap(),
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::LegacySourceCleanup,
        target,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialFence::new(2).unwrap(),
        None,
    )
    .unwrap()
}

fn target(import_id: u8, digest: u8, version: u64) -> CredentialBrokerTarget {
    CredentialBrokerTarget::ExactLegacySource(CredentialLegacyCleanupBinding::from_parts(
        CredentialOperationId::from_bytes([import_id; 16]).unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialVersionRef::new(ProviderId::new("openai").unwrap(), version).unwrap(),
        CredentialBindingDigest::from_measured([digest; 32]).unwrap(),
    ))
}

#[test]
fn legacy_absence_digest_binds_original_import_and_ignores_ticket_reissue() {
    let observe = |target, attempt| {
        super::readback_observation::legacy_observation(&command(target, attempt)).unwrap()
    };
    let original = observe(target(3, 7, 1), 1);
    assert!(!original.present());
    assert_eq!(original.binding(), observe(target(3, 7, 1), 2).binding());
    for changed in [target(4, 7, 1), target(3, 8, 1), target(3, 7, 2)] {
        assert_ne!(original.binding(), observe(changed, 1).binding());
    }
}

#[test]
fn legacy_absence_digest_rejects_unbound_target() {
    assert!(
        super::readback_observation::legacy_observation(&command(
            CredentialBrokerTarget::LegacySource,
            1
        ))
        .is_err()
    );
}

#[test]
fn exact_absence_input_requires_bound_cleanup_and_rejects_presence() {
    use super::ExactAbsenceReadback;
    assert!(ExactAbsenceReadback::new(command(CredentialBrokerTarget::LegacySource, 1)).is_err());
    assert!(
        ExactAbsenceReadback::new(command(target(3, 7, 1), 1))
            .unwrap()
            .observe_service_presence(true)
            .is_err()
    );
    assert!(
        !ExactAbsenceReadback::new(command(target(3, 7, 1), 1))
            .unwrap()
            .observe_service_presence(false)
            .unwrap()
            .present()
    );
}
