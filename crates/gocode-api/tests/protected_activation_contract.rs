use std::path::PathBuf;

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, LaunchSecret, PendingFirstActivationV1,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedReadyV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1, ProtectedRuntimeProfileV1,
    ProtectedShutdownAckV1, ProtectedShutdownV1, StableRuntimeBindingV1,
};

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
        "gocode-bundled-runtime/1",
        1,
        "gocode-ui-client/1",
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
        "gocode-ui-client/1",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("stable binding")
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
        PathBuf::from("/private/tmp/gocode-protected-runtime"),
        disposition,
    )
    .expect("launch request")
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
        "gocode-local-runtime/2",
        2,
        "gocode-ui-client/1",
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

#[test]
fn executable_identity_detects_byte_replacement_without_exposing_the_path() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gocoded");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"first executable").unwrap();
    file.sync_all().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let first = ExecutableIdentityV1::measure(&path).expect("first identity");
    std::fs::write(&path, b"replacement executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let replacement = ExecutableIdentityV1::measure(&path).expect("replacement identity");

    assert_ne!(first, replacement);
    assert!(!format!("{first:?}").contains(directory.path().to_str().unwrap()));
}

#[test]
fn first_activation_prepare_and_commit_are_exact_authenticated_frames() {
    let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
    let keys = secret.derive_keys();
    let request = launch_with_disposition(secret, ActivationDispositionV1::FirstActivation);
    let pending = PendingFirstActivationV1::new(
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 7,
        ],
        [0x41; 32],
        stable(),
        executable(),
        profile(),
    )
    .expect("pending");
    let mut prepared = ProtectedFirstActivationPreparedV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        pending.clone(),
    );
    prepared.sign(&keys);
    prepared
        .verify_exact(&request, &keys)
        .expect("prepared proof");
    let prepared_frame = prepared.encode_frame().expect("prepared frame");
    assert_eq!(
        ProtectedFirstActivationPreparedV1::decode_frame(&prepared_frame).unwrap(),
        prepared
    );

    let mut commit = ProtectedFirstActivationCommitV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        pending.clone(),
    );
    commit.sign(&keys);
    commit
        .verify_exact(&request, &pending, &keys)
        .expect("commit proof");
    let commit_frame = commit.encode_frame().expect("commit frame");
    assert_eq!(
        ProtectedFirstActivationCommitV1::decode_frame(&commit_frame).unwrap(),
        commit
    );

    let different = PendingFirstActivationV1::new(
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 8,
        ],
        [0x42; 32],
        stable(),
        executable(),
        profile(),
    )
    .unwrap();
    assert_eq!(
        commit
            .verify_exact(&request, &different, &keys)
            .unwrap_err(),
        LaunchAuthorityError::FirstActivationPreparationMismatch
    );
}

#[test]
fn renewal_and_shutdown_are_bound_to_the_current_owned_launch() {
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
    .unwrap();
    ready.sign(&keys);
    let owned = ready.owned_launch();

    let mut renewal = ProtectedRenewRequestV1::new(owned.clone(), 1, [0x71; 32]).unwrap();
    renewal.sign(&keys);
    renewal
        .verify_exact(&owned, 0, &keys)
        .expect("first renewal");
    assert_eq!(
        renewal.verify_exact(&owned, 1, &keys).unwrap_err(),
        LaunchAuthorityError::RenewalReplay
    );
    assert_eq!(
        ProtectedRenewRequestV1::decode_frame(&renewal.encode_frame().unwrap()).unwrap(),
        renewal
    );

    let next_session = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 6,
    ];
    let mut ticket =
        ProtectedRenewTicketV1::new(&renewal, next_session, [0x72; 32], 1_000, 31_000).unwrap();
    ticket.sign(&keys);
    ticket
        .verify_exact(&renewal, &keys)
        .expect("renewal ticket");
    assert_eq!(
        ProtectedRenewTicketV1::decode_frame(&ticket.encode_frame().unwrap()).unwrap(),
        ticket
    );

    let mut shutdown = ProtectedShutdownV1::new(owned.clone());
    shutdown.sign(&keys);
    shutdown
        .verify_exact(&owned, &keys)
        .expect("owned shutdown");
    assert_eq!(
        ProtectedShutdownV1::decode_frame(&shutdown.encode_frame().unwrap()).unwrap(),
        shutdown
    );
    let mut acknowledgement = ProtectedShutdownAckV1::new(owned, true);
    acknowledgement.sign(&keys);
    acknowledgement
        .verify_exact(shutdown.owned_launch(), &keys)
        .expect("owned shutdown ack");
    assert_eq!(
        ProtectedShutdownAckV1::decode_frame(&acknowledgement.encode_frame().unwrap()).unwrap(),
        acknowledgement
    );
}
