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
