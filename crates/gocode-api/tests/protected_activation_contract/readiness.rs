
#[test]
fn v2_ready_roundtrips_every_provider_readiness_variant() {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let keys = request.derive_keys();
    for variant in [
        ProviderActivationReadinessV1::Ready,
        ProviderActivationReadinessV1::CredentialMissing,
        ProviderActivationReadinessV1::CredentialAccessDenied,
        ProviderActivationReadinessV1::CredentialIdentityMismatch,
        ProviderActivationReadinessV1::SecureStoreUnavailable,
    ] {
        let base_ready = signed_ready(
            request.launch_authority_id(),
            request.desktop_host_instance_id(),
            &keys,
        );
        let mut ready =
            ProtectedReadyV2::new(base_ready, openai_binding(), variant).unwrap();
        ready.sign(&keys);
        ready
            .verify_exact(&request, &keys)
            .expect("exact V2 readiness for every disposition");
        let decoded =
            ProtectedReadyV2::decode_frame(&ready.encode_frame().unwrap()).unwrap();
        assert_eq!(decoded.provider_readiness(), variant);
    }
}

#[test]
fn v2_ready_rejects_unknown_readiness_enum() {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let keys = request.derive_keys();
    let base_ready = signed_ready(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        &keys,
    );
    let mut ready =
        ProtectedReadyV2::new(base_ready, openai_binding(), ProviderActivationReadinessV1::Ready)
            .unwrap();
    ready.sign(&keys);
    let mut frame = ready.encode_frame().unwrap();

    // The V2 readiness value (key 4) immediately precedes the outer proof
    // (key 5, 32-byte byte string). Replace `Ready` (0) with unknown 5.
    let proof_key = [0x05, 0x58, 0x20];
    let proof_offset = frame
        .windows(proof_key.len())
        .rposition(|window| window == proof_key)
        .expect("outer V2 readiness proof key");
    assert_eq!(frame[proof_offset - 2], 0x04, "readiness field key");
    assert_eq!(frame[proof_offset - 1], 0x00, "Ready wire code");
    frame[proof_offset - 1] = 0x05;
    assert!(ProtectedReadyV2::decode_frame(&frame).is_err());
}

#[test]
fn v2_ready_rejects_tampered_readiness_disposition() {
    let request = launch_v2(LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret"));
    let keys = request.derive_keys();
    let base_ready = signed_ready(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        &keys,
    );
    let mut ready =
        ProtectedReadyV2::new(base_ready, openai_binding(), ProviderActivationReadinessV1::Ready)
            .unwrap();
    ready.sign(&keys);
    let mut frame = ready.encode_frame().unwrap();

    let proof_key = [0x05, 0x58, 0x20];
    let proof_offset = frame
        .windows(proof_key.len())
        .rposition(|window| window == proof_key)
        .expect("outer V2 readiness proof key");
    frame[proof_offset - 1] = 0x01; // Ready -> CredentialMissing

    let tampered = ProtectedReadyV2::decode_frame(&frame).expect("structurally valid frame");
    assert_eq!(
        tampered.verify_exact(&request, &keys).unwrap_err(),
        LaunchAuthorityError::ReadinessProofMismatch
    );
}

#[test]
fn tauri_has_no_direct_secure_store_dependency() {
    let manifest = include_str!("../../../../apps/desktop/src-tauri/Cargo.toml");
    assert!(
        !manifest.contains("gocode-secure-store"),
        "Tauri must not depend directly on gocode-secure-store"
    );
}
