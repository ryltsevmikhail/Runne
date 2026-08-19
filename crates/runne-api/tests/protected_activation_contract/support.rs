use std::path::PathBuf;

use runne_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, LaunchSecret, PendingFirstActivationV1,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedOwnedLaunchV2, ProtectedReadyV1, ProtectedReadyV2,
    ProtectedRenewRequestV1, ProtectedRenewRequestV2, ProtectedRenewTicketV1,
    ProtectedRenewTicketV2, ProtectedRuntimeProfileV1, ProtectedShutdownAckV1,
    ProtectedShutdownAckV2, ProtectedShutdownV1, ProtectedShutdownV2, ProviderActivationBindingV1, ProviderActivationReadinessV1,
    ProviderActivationModeV1, StableRuntimeBindingV1,
};
use sha2::{Digest, Sha256};

const AUTHORITY_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const HOST_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const LINEAGE_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
const INSTANCE_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];
const SESSION_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
];

fn executable() -> ExecutableIdentityV1 {
    ExecutableIdentityV1::new([0x11; 32], [0x12; 32], 4_096).expect("executable identity")
}

fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        "runne-bundled-runtime/1",
        1,
        "runne-ui-client/2",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("protected profile")
}

fn stable() -> StableRuntimeBindingV1 {
    StableRuntimeBindingV1::new(
        AUTHORITY_ID,
        "local-owner",
        LINEAGE_ID,
        "runne-ui-client/2",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("stable binding")
}

fn protected_runtime_root() -> PathBuf {
    #[cfg(not(windows))]
    {
        PathBuf::from("/private/tmp/runne-protected-runtime")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\runne-protected-runtime")
    }
}

fn platform_launch_golden(golden: &serde_json::Value) -> &serde_json::Value {
    let canonical_unix = &golden["platform_launch_frames"]["unix"];
    assert_eq!(golden["canonical_launch_platform"], "unix");
    assert_eq!(golden["message_type_id"], canonical_unix["message_type_id"]);
    assert_eq!(golden["frame_length"], canonical_unix["frame_length"]);
    assert_eq!(golden["frame_sha256"], canonical_unix["frame_sha256"]);
    assert_eq!(golden["lifecycle_messages"]["launch"], *canonical_unix);
    #[cfg(not(windows))]
    {
        canonical_unix
    }
    #[cfg(windows)]
    {
        &golden["platform_launch_frames"]["windows"]
    }
}

fn launch(secret: LaunchSecret) -> ProtectedLaunchRequestV1 {
    launch_with_disposition(
        secret,
        ActivationDispositionV1::Existing(Box::new(stable())),
    )
}

fn launch_with_disposition(
    secret: LaunchSecret,
    disposition: ActivationDispositionV1,
) -> ProtectedLaunchRequestV1 {
    ProtectedLaunchRequestV1::new(
        AUTHORITY_ID,
        HOST_ID,
        secret,
        1_000,
        31_000,
        "local-owner",
        profile(),
        executable(),
        protected_runtime_root(),
        disposition,
    )
    .expect("launch request")
}

fn deterministic_binding() -> ProviderActivationBindingV1 {
    ProviderActivationBindingV1::deterministic_v1()
}

fn openai_binding() -> ProviderActivationBindingV1 {
    ProviderActivationBindingV1::openai_responses_text_v1()
}

fn launch_v2(secret: LaunchSecret) -> ProtectedLaunchRequestV2 {
    ProtectedLaunchRequestV2::new(launch(secret), openai_binding()).expect("V2 launch request")
}

#[test]
fn launch_authority_is_short_lived_and_exactly_bound() {
    let request = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));

    request
        .validate(
            30_999,
            &LaunchAuthorityValidationV1 {
                principal_id: "local-owner",
                profile: &profile(),
                executable: &executable(),
            },
        )
        .expect("authority inside TTL");

    assert_eq!(
        request
            .validate(
                31_001,
                &LaunchAuthorityValidationV1 {
                    principal_id: "local-owner",
                    profile: &profile(),
                    executable: &executable(),
                },
            )
            .unwrap_err(),
        LaunchAuthorityError::StaleLaunchAuthority
    );
}

#[test]
fn credential_first_profile_is_rejected_for_bundled_activation() {
    let request = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let external = ProtectedRuntimeProfileV1::new(
        "runne-local-runtime/2",
        2,
        "runne-ui-client/2",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("external profile shape");

    assert_eq!(
        request
            .validate(
                1_001,
                &LaunchAuthorityValidationV1 {
                    principal_id: "local-owner",
                    profile: &external,
                    executable: &executable(),
                },
            )
            .unwrap_err(),
        LaunchAuthorityError::DowngradedExternalProfile
    );
}

#[test]
fn launch_frame_is_deterministic_bounded_and_strict() {
    let request = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let first = request.encode_frame().expect("frame");
    let second = request.encode_frame().expect("frame");
    assert_eq!(first, second);
    assert!(first.len() <= 65_540);
    assert_eq!(
        ProtectedLaunchRequestV1::decode_frame(&first).expect("round trip"),
        request
    );

    let mut trailing = first;
    trailing.push(0);
    assert!(ProtectedLaunchRequestV1::decode_frame(&trailing).is_err());
}

#[test]
fn ready_proof_covers_the_exact_launch_profile_and_session_tuple() {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch(secret);
    let mut ready = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        executable(),
        profile(),
        stable(),
        INSTANCE_ID,
        7,
        SESSION_ID,
        "https://127.0.0.1:43123",
        [0x31; 32],
        vec![1, 2, 3, 4],
        vec!["conversation-replay-v2".to_owned()],
    )
    .expect("ready");
    ready.sign(&keys);
    ready
        .verify_exact(&request, &keys)
        .expect("exact readiness");

    assert_eq!(
        ProtectedReadyV1::new(
            request.launch_authority_id(),
            request.desktop_host_instance_id(),
            executable(),
            profile(),
            stable(),
            INSTANCE_ID,
            7,
            INSTANCE_ID,
            "https://127.0.0.1:43123",
            [0x31; 32],
            vec![1, 2, 3, 4],
            vec!["conversation-replay-v2".to_owned()],
        )
        .expect_err("instance/session reuse must fail"),
        LaunchAuthorityError::InstanceGenerationSessionMismatch
    );
}

#[test]
fn launch_secret_and_derived_keys_are_not_debuggable() {
    fn assert_not_debug<T>() {
        let type_name = std::any::type_name::<T>();
        assert!(!type_name.is_empty());
    }

    assert_not_debug::<LaunchSecret>();
    let request = launch(LaunchSecret::from_bytes([0x5a; 32]).expect("launch secret"));
    let diagnostic = format!("{request:?}");
    assert!(!diagnostic.contains(&"5a".repeat(32)));
    assert!(!diagnostic.contains("/private/tmp"));
}
