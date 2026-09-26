use super::desktop_peer_digest;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
const LINUX_TEST_RELEASE: [u8; 32] = [1; 32];
#[cfg(target_os = "linux")]
const LINUX_TEST_QUALIFICATION: [u8; 32] = [2; 32];
#[cfg(target_os = "linux")]
const LINUX_TEST_AUTHORITY: [u8; 16] = linux_test_id(3);
#[cfg(target_os = "linux")]
const LINUX_TEST_HOST: [u8; 16] = linux_test_id(4);
#[cfg(target_os = "linux")]
const LINUX_TEST_GENERATION: u64 = 17;

#[cfg(target_os = "linux")]
const fn linux_test_id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

#[cfg(target_os = "linux")]
fn linux_test_prepare(
    binding: [u8; 32],
) -> (
    runne_api::ProtectedCredentialEnrollmentPrepareV2,
    runne_api::ProtectedOwnedLaunchV2,
    runne_api::ProtectedActivationKeys,
) {
    use runne_api::{
        ActivationDispositionV1, ExecutableIdentityV1, LaunchSecret,
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedLaunchRequestV1, ProtectedReadyV1,
        ProtectedRuntimeProfileV1, ProviderActivationBindingV1, StableRuntimeBindingV1,
    };
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let request = ProtectedLaunchRequestV1::new(
        LINUX_TEST_AUTHORITY,
        LINUX_TEST_HOST,
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let ready = ProtectedReadyV1::new(
        LINUX_TEST_AUTHORITY,
        LINUX_TEST_HOST,
        request.executable().clone(),
        profile,
        StableRuntimeBindingV1::new(
            linux_test_id(10),
            "local-owner",
            linux_test_id(11),
            "fixture",
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        linux_test_id(12),
        1,
        linux_test_id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let owned = runne_api::ProtectedOwnedLaunchV2::new(
        ready.owned_launch(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
    )
    .unwrap();
    let mut prepare = runne_api::ProtectedCredentialEnrollmentPrepareV2::new(
        owned.clone(),
        1,
        [21; 32],
        LINUX_TEST_RELEASE,
        LINUX_TEST_QUALIFICATION,
        binding,
        LINUX_TEST_GENERATION,
    )
    .unwrap();
    prepare.sign(&keys);
    (prepare, owned, keys)
}

#[test]
fn peer_claim_changes_for_every_authoritative_binding() {
    let base = desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 7);
    for changed in [
        desktop_peer_digest([8; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [8; 32], [3; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [8; 32], 4, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 8, [5; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [8; 16], [6; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [8; 16], 7),
        desktop_peer_digest([1; 32], [2; 32], [3; 32], 4, [5; 16], [6; 16], 8),
    ] {
        assert_ne!(base, changed);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_peer_binding_child_verifies_parent_claim() {
    let Ok(socket) = std::env::var("RUNNE_LINUX_PEER_TEST_SOCKET") else {
        return;
    };
    let stream = UnixStream::connect(socket).unwrap();
    let linux_binding: [u8; 32] = hex::decode(
        std::env::var("RUNNE_LINUX_PEER_TEST_BINDING").unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let generic_binding: [u8; 32] = hex::decode(
        std::env::var("RUNNE_LINUX_PEER_TEST_GENERIC").unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let (prepare, owned, keys) = linux_test_prepare(linux_binding);
    let claims = prepare.verify_exact_view(&owned, 0, &keys).unwrap();
    assert!(crate::verify_linux_enrollment_peer(&stream, &claims));
    let (prepare, owned, keys) = linux_test_prepare(generic_binding);
    let claims = prepare.verify_exact_view(&owned, 0, &keys).unwrap();
    assert!(!crate::verify_linux_enrollment_peer(&stream, &claims));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_peer_binding_matches_kernel_peer_and_rejects_old_generic_claim() {
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("peer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let process_start = crate::provider_credential_broker::observe_current_process_start()
        .unwrap();
    let linux_binding = crate::linux_enrollment_peer_binding(
        LINUX_TEST_RELEASE,
        LINUX_TEST_AUTHORITY,
        LINUX_TEST_HOST,
        LINUX_TEST_GENERATION,
    )
    .unwrap();
    let generic_binding = desktop_peer_digest(
        LINUX_TEST_RELEASE,
        [5; 32],
        process_start,
        rustix::process::geteuid().as_raw(),
        LINUX_TEST_AUTHORITY,
        LINUX_TEST_HOST,
        LINUX_TEST_GENERATION,
    );
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["linux_peer_binding_child_verifies_parent_claim", "--nocapture"])
        .env("RUNNE_LINUX_PEER_TEST_SOCKET", &socket)
        .env("RUNNE_LINUX_PEER_TEST_BINDING", hex::encode(linux_binding))
        .env("RUNNE_LINUX_PEER_TEST_GENERIC", hex::encode(generic_binding))
        .spawn()
        .unwrap();
    let (_stream, _) = listener.accept().unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
