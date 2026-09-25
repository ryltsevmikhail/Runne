use std::os::unix::net::UnixStream;

use runne_api::{
    ExecutableIdentityV1, LaunchSecret, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
    ProtectedCredentialEnrollmentPrepareV2, ProtectedLaunchRequestV1, ProtectedOwnedLaunchV2,
    ProtectedReadyV1, ProtectedRuntimeProfileV1, ProviderActivationBindingV1,
    StableRuntimeBindingV1,
};
use runne_macos_process_identity::MacOsLocalPeerProcessIdentity;

use super::{
    super::{
        enrollment_daemon_installed::tests::signed_fixture_admission,
        enrollment_desktop_peer_claim::desktop_peer_digest,
    },
    retained_claims_match,
};

const fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn view(
    release: [u8; 32],
    qualification: [u8; 32],
    binding: [u8; 32],
    authority: [u8; 16],
    host: [u8; 16],
    supervisor: u64,
) -> (
    ProtectedCredentialEnrollmentPrepareV2,
    ProtectedOwnedLaunchV2,
    runne_api::ProtectedActivationKeys,
) {
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let request = ProtectedLaunchRequestV1::new(
        authority,
        host,
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        "/tmp/runtime".into(),
        runne_api::ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let ready = ProtectedReadyV1::new(
        authority,
        host,
        request.executable().clone(),
        profile,
        StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap(),
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let owned = ProtectedOwnedLaunchV2::new(
        ready.owned_launch(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
    )
    .unwrap();
    let mut prepare = ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [21; 32],
        release,
        qualification,
        binding,
        supervisor,
    )
    .unwrap();
    prepare.sign(&keys);
    (prepare, owned, keys)
}

#[test]
fn retained_claims_accept_only_the_exact_mac_signed_v2_view() {
    let fixture = signed_fixture_admission();
    let (stream, _peer_stream) = UnixStream::pair().unwrap();
    let peer = MacOsLocalPeerProcessIdentity::capture(&stream).unwrap();
    let authority = id(1);
    let host = id(2);
    let supervisor = 1;
    let binding = desktop_peer_digest(
        fixture.release,
        fixture.admission.desktop_sha256,
        peer.process_start_digest(),
        peer.euid(),
        authority,
        host,
        supervisor,
    );
    let (prepare, owned, keys) = view(
        fixture.release,
        fixture.qualification,
        binding,
        authority,
        host,
        supervisor,
    );
    let claims = prepare.verify_exact_view(&owned, 0, &keys).unwrap();
    assert!(retained_claims_match(
        &fixture.admission,
        &peer,
        &claims,
        fixture.expires_at - 1
    ));
    for (release, qualification, peer_binding, authority, host, supervisor) in [
        (
            [31; 32],
            fixture.qualification,
            binding,
            authority,
            host,
            supervisor,
        ),
        (
            fixture.release,
            [32; 32],
            binding,
            authority,
            host,
            supervisor,
        ),
        (
            fixture.release,
            fixture.qualification,
            [33; 32],
            authority,
            host,
            supervisor,
        ),
        (
            fixture.release,
            fixture.qualification,
            binding,
            authority,
            host,
            2,
        ),
        (
            fixture.release,
            fixture.qualification,
            binding,
            id(31),
            host,
            supervisor,
        ),
        (
            fixture.release,
            fixture.qualification,
            binding,
            authority,
            id(32),
            supervisor,
        ),
    ] {
        let (prepare, owned, keys) = view(
            release,
            qualification,
            peer_binding,
            authority,
            host,
            supervisor,
        );
        let claims = prepare.verify_exact_view(&owned, 0, &keys).unwrap();
        assert!(!retained_claims_match(
            &fixture.admission,
            &peer,
            &claims,
            fixture.expires_at - 1
        ));
    }
}
