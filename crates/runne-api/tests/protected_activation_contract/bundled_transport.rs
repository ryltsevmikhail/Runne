#[test]
fn bundled_transport_accepts_gocode_and_rejects_same_shape_runne_alias() {
    let canonical = launch(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    canonical
        .validate(
            1_001,
            &LaunchAuthorityValidationV1 {
                principal_id: "local-owner",
                profile: &profile(),
                executable: &executable(),
            },
        )
        .expect("exact GOCODE bundled transport is accepted");

    let runne_profile = ProtectedRuntimeProfileV1::new(
        "runne-bundled-runtime/1",
        1,
        "gocode-ui-client/2",
        [0x21; 32],
        [0x22; 32],
    )
    .expect("otherwise-valid RUNNE profile shape");
    let runne_request = ProtectedLaunchRequestV1::new(
        AUTHORITY_ID,
        HOST_ID,
        LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"),
        1_000,
        31_000,
        "local-owner",
        runne_profile.clone(),
        executable(),
        protected_runtime_root(),
        ActivationDispositionV1::Existing(Box::new(stable())),
    )
    .expect("otherwise-valid RUNNE request shape");
    assert_eq!(
        runne_request
            .validate(
                1_001,
                &LaunchAuthorityValidationV1 {
                    principal_id: "local-owner",
                    profile: &runne_profile,
                    executable: &executable(),
                },
            )
            .unwrap_err(),
        LaunchAuthorityError::DowngradedExternalProfile
    );
}
