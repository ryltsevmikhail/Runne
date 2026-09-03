use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLease,
    CredentialLifecycleRevision, CredentialVersionRef, ProviderId,
};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead, SecureStoreError,
};

use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceSessionAuthenticator, LaunchSecret,
};

use super::CredentialServiceRuntimeGateway;
use super::credential_service_registration::{
    ExpectedCredentialServiceRegistration, accept_registration_frames,
};

#[tokio::test]
async fn service_gateway_fails_closed_before_authenticated_registration() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let gateway = CredentialServiceRuntimeGateway::new(store, tokio::runtime::Handle::current());
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let provider = ProviderId::new("deepseek").unwrap();
    let reference = CredentialVersionRef::new(provider, 1).unwrap();
    let capability =
        lifecycle.issue_dispatch(CredentialLease::new(reference, [1; 16], i64::MAX, 1).unwrap());
    let read = ProviderCredentialDispatchRead::new(
        &capability,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        [9; 32],
    )
    .unwrap();

    assert_eq!(
        gateway.materialize_active(read).unwrap_err(),
        SecureStoreError::Unavailable
    );
}

#[tokio::test]
async fn service_gateway_accepts_only_exact_rejoin_and_newer_runtime_supersession() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let gateway = CredentialServiceRuntimeGateway::new(store, tokio::runtime::Handle::current());
    let first = binding(2, uuid(1), 11, 13, 1, [4; 32]);
    gateway.install(session(&first, 7)).unwrap();

    let exact_rejoin = binding(3, uuid(2), 11, 13, 2, [4; 32]);
    gateway.install(session(&exact_rejoin, 7)).unwrap();

    let runtime_restart = binding(3, uuid(3), 12, 13, 1, [4; 32]);
    gateway.install(session(&runtime_restart, 8)).unwrap();

    assert!(gateway.install(session(&exact_rejoin, 7)).is_err());
    assert!(
        gateway
            .install(session(&binding(4, uuid(3), 12, 13, 4, [9; 32]), 8))
            .is_err()
    );
}

fn session(
    binding: &CredentialServiceRegistrationBinding,
    secret: u8,
) -> super::credential_service_registration::CredentialServiceRuntimeSession {
    let keys = LaunchSecret::from_bytes([secret; 32])
        .unwrap()
        .derive_keys();
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&claim, binding, 99)
        .unwrap();
    let acknowledgement = authenticator
        .registration_ack(verified, 99)
        .unwrap()
        .into_bytes();
    accept_registration_frames(
        &keys,
        &ExpectedCredentialServiceRegistration::from_binding(binding),
        &claim,
        &acknowledgement,
        99,
    )
    .unwrap()
}

fn binding(
    epoch: u8,
    protected_session: [u8; 16],
    runtime_generation: u64,
    supervisor_generation: u64,
    join_attempt: u64,
    release: [u8; 32],
) -> CredentialServiceRegistrationBinding {
    CredentialServiceRegistrationBinding::new(
        [epoch; 16],
        protected_session,
        runtime_generation,
        runtime_generation,
        supervisor_generation,
        14,
        [3; 32],
        release,
        [epoch.wrapping_add(u8::try_from(join_attempt).unwrap()); 16],
        join_attempt,
        30_100,
    )
    .unwrap()
}

const fn uuid(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}
