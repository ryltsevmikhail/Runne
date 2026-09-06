use runne_credential_service_core::{
    CredentialBackendResult, CredentialRuntimeReadEffect, CredentialRuntimeReadObservation,
};
use runne_provider::{CredentialMaterial, CredentialVersionRef, ProviderId};
use zeroize::Zeroizing;

use crate::service_backend::ServiceBackend;

mod process_canary;

const CANARY: &str = "runne-d1-1c-service-canary-4f7d2a";

#[cfg(target_os = "macos")]
#[test]
fn keychain_record_decode_error_is_closed_over_oversized_material() {
    let mut oversized = Zeroizing::new(Vec::new());
    while oversized.len() <= CredentialMaterial::MAX_BYTES {
        oversized.extend_from_slice(CANARY.as_bytes());
    }

    let Err(debug) = crate::keychain::KeychainBackend::decode_record_fixture_debug(&oversized)
    else {
        panic!("oversized Keychain material must be rejected");
    };

    assert_eq!(debug, "AccessDenied");
    assert!(!debug.contains(CANARY));
    assert!(!debug.contains("material"));
}

#[cfg(feature = "test-support")]
#[test]
fn memory_backend_point_of_use_read_keeps_material_in_zeroizing_storage() {
    let reference =
        CredentialVersionRef::new(ProviderId::new("fixture-provider").unwrap(), 1).unwrap();
    let material =
        CredentialMaterial::from_zeroizing(Zeroizing::new(CANARY.as_bytes().to_vec())).unwrap();
    let backend = ServiceBackend::memory_fixture(reference.clone(), material);

    let CredentialRuntimeReadObservation::PointOfUse(result) =
        backend.read(&CredentialRuntimeReadEffect::PointOfUse(&reference))
    else {
        panic!("expected point-of-use observation");
    };
    let CredentialBackendResult::Observed(material) = result else {
        panic!("expected observed material");
    };
    let material = material.into_zeroizing();

    assert_eq!(material.as_slice(), CANARY.as_bytes());
    let closed_debug = format!("{:?}", CredentialBackendResult::<()>::Absent);
    assert_eq!(closed_debug, "Absent");
    assert!(!closed_debug.contains(CANARY));
    assert!(!closed_debug.contains("material"));
}
