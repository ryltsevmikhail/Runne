use super::{
    MacOsCodeIdentityExpectationV1, QualificationBootstrapClientArtifactV1,
    QualificationBootstrapClientV1, SignedInstalledReleaseVerificationErrorV2, UpdateMetadataV2,
    verify_exact_signed_installed_release_v2, verify_signed_update_metadata_v2,
};

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", cdhash.to_string().repeat(40))
        .unwrap()
}

fn client(
    desktop_cdhash: char,
    executor_cdhash: char,
    root_cdhash: char,
    executor_image: char,
    root_image: char,
) -> QualificationBootstrapClientV1 {
    QualificationBootstrapClientV1::new(
        identity("com.runne.desktop", desktop_cdhash),
        identity("runned", '3'),
        QualificationBootstrapClientArtifactV1::new(
            identity("com.runne.native-dpk-executor", executor_cdhash),
            hash(executor_image),
        )
        .unwrap(),
        QualificationBootstrapClientArtifactV1::new(
            identity("com.runne.qualification-root-service", root_cdhash),
            hash(root_image),
        )
        .unwrap(),
        hash('c'),
    )
    .unwrap()
}

fn metadata_with_client() -> (UpdateMetadataV2, super::UpdateTrustRootV2) {
    let (mut metadata, trust, _) = super::tests::pinned_test_facts();
    metadata.targets.target.native_enrollment_tuple = None;
    metadata.targets.target.native_enrollment_tuple_v3 =
        Some(super::tuple_v3_tests::tuple(&metadata.targets.target));
    metadata.targets.target.qualification_bootstrap_client_v1 =
        Some(client('1', 'a', 'b', 'a', 'b'));
    super::tuple_v3_tests::resign_targets(&mut metadata);
    (metadata, trust)
}

fn change_client(
    metadata: &UpdateMetadataV2,
    field: &str,
    replacement: serde_json::Value,
) -> UpdateMetadataV2 {
    let mut value = serde_json::to_value(metadata).unwrap();
    value["targets"]["target"]["qualificationBootstrapClientV1"][field] = replacement;
    serde_json::from_value(value).unwrap()
}

fn change_client_child(
    metadata: &UpdateMetadataV2,
    child: &str,
    field: &str,
    replacement: serde_json::Value,
) -> UpdateMetadataV2 {
    let mut value = serde_json::to_value(metadata).unwrap();
    value["targets"]["target"]["qualificationBootstrapClientV1"][child][field] = replacement;
    serde_json::from_value(value).unwrap()
}

fn change_client_grandchild(
    metadata: &UpdateMetadataV2,
    child: &str,
    grandchild: &str,
    field: &str,
    replacement: serde_json::Value,
) -> UpdateMetadataV2 {
    let mut value = serde_json::to_value(metadata).unwrap();
    value["targets"]["target"]["qualificationBootstrapClientV1"][child][grandchild][field] =
        replacement;
    serde_json::from_value(value).unwrap()
}

#[test]
fn unqualified_v3_bootstrap_descriptor_is_signed_metadata_only() {
    let (metadata, trust) = metadata_with_client();
    let verified = verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    let client = verified
        .target()
        .qualification_bootstrap_client_v1
        .as_ref()
        .unwrap();
    assert_eq!(client.desktop_identity().identifier(), "com.runne.desktop");
    assert_eq!(client.runtime_identity().identifier(), "runned");
    assert_eq!(
        client.executor_identity().identifier(),
        "com.runne.native-dpk-executor"
    );
    assert_eq!(client.executor_image_sha256(), hash('a'));
    assert_eq!(
        client.root_identity().identifier(),
        "com.runne.qualification-root-service"
    );
    assert_eq!(client.root_image_sha256(), hash('b'));
    assert_eq!(client.qualification_profile_sha256(), [0xcc; 32]);
    assert_ne!(verified.target_manifest_digest(), [0; 32]);
    assert!(verified.qualified_release_candidate_v3().is_none());
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &serde_json::to_vec(&metadata).unwrap(),
            &trust,
            [1; 32],
            100,
        ),
        Err(SignedInstalledReleaseVerificationErrorV2::Unqualified)
    );
}

#[test]
fn descriptor_requires_v3_and_exact_roles_without_collisions() {
    let (mut missing, trust, _) = super::tests::pinned_test_facts();
    missing.targets.target.qualification_bootstrap_client_v1 =
        Some(client('1', 'a', 'b', 'a', 'b'));
    super::tuple_v3_tests::resign_targets(&mut missing);
    assert_eq!(
        verify_signed_update_metadata_v2(&missing, &trust, 100),
        Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
    );

    for bad in [
        client('5', 'a', 'b', 'a', 'b'),
        client('1', '1', 'b', 'a', 'b'),
        client('1', 'a', '3', 'a', 'b'),
        client('1', 'a', 'b', '2', 'b'),
        client('1', 'a', 'a', 'a', 'b'),
        client('1', 'a', 'b', 'a', 'a'),
    ] {
        let (mut metadata, trust) = metadata_with_client();
        metadata.targets.target.qualification_bootstrap_client_v1 = Some(bad);
        super::tuple_v3_tests::resign_targets(&mut metadata);
        assert_eq!(
            verify_signed_update_metadata_v2(&metadata, &trust, 100),
            Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
        );
    }

    for (child, field, replacement) in [
        (
            "runtimeIdentity",
            "cdhash",
            serde_json::json!("5".repeat(40)),
        ),
        ("executor", "imageSha256", serde_json::json!(hash('0'))),
        ("root", "imageSha256", serde_json::json!(hash('0'))),
    ] {
        let (metadata, trust) = metadata_with_client();
        let mut metadata = change_client_child(&metadata, child, field, replacement);
        super::tuple_v3_tests::resign_targets(&mut metadata);
        assert_eq!(
            verify_signed_update_metadata_v2(&metadata, &trust, 100),
            Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
        );
    }
    for (field, replacement) in [
        ("teamIdentifier", serde_json::json!("ABCDEFGHIJ")),
        ("identifier", serde_json::json!("com.runne.desktop")),
    ] {
        let (metadata, trust) = metadata_with_client();
        let mut metadata =
            change_client_grandchild(&metadata, "executor", "identity", field, replacement);
        super::tuple_v3_tests::resign_targets(&mut metadata);
        assert_eq!(
            verify_signed_update_metadata_v2(&metadata, &trust, 100),
            Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
        );
    }
}

#[test]
fn descriptor_rejects_invalid_hash_schema_protocol_and_endpoint() {
    for (field, replacement) in [
        ("schemaVersion", serde_json::json!(2)),
        ("protocolVersion", serde_json::json!(2)),
        ("desktopEndpoint", serde_json::json!("com.runne.untrusted")),
        ("runtimeEndpoint", serde_json::json!("com.runne.untrusted")),
        ("rootEndpoint", serde_json::json!("com.runne.untrusted")),
        ("qualificationProfileSha256", serde_json::json!("bad")),
    ] {
        let (metadata, trust) = metadata_with_client();
        let mut metadata = change_client(&metadata, field, replacement);
        super::tuple_v3_tests::resign_targets(&mut metadata);
        assert_eq!(
            verify_signed_update_metadata_v2(&metadata, &trust, 100),
            Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
        );
    }
    let (metadata, trust) = metadata_with_client();
    let mut metadata = change_client(
        &metadata,
        "qualificationProfileSha256",
        serde_json::json!("A".repeat(64)),
    );
    super::tuple_v3_tests::resign_targets(&mut metadata);
    assert_eq!(
        verify_signed_update_metadata_v2(&metadata, &trust, 100),
        Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
    );
    let (metadata, trust) = metadata_with_client();
    let mut metadata = change_client(
        &metadata,
        "qualificationProfileSha256",
        serde_json::json!(hash('0')),
    );
    super::tuple_v3_tests::resign_targets(&mut metadata);
    assert_eq!(
        verify_signed_update_metadata_v2(&metadata, &trust, 100),
        Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata)
    );
}

#[test]
fn descriptor_mutation_breaks_signature_and_changes_signed_manifest_digest() {
    let (metadata, trust) = metadata_with_client();
    let original = verify_signed_update_metadata_v2(&metadata, &trust, 100)
        .unwrap()
        .target_manifest_digest();
    let mut changed = change_client(
        &metadata,
        "qualificationProfileSha256",
        serde_json::json!(hash('d')),
    );
    assert_eq!(
        verify_signed_update_metadata_v2(&changed, &trust, 100),
        Err(SignedInstalledReleaseVerificationErrorV2::TargetsQuorum)
    );
    super::tuple_v3_tests::resign_targets(&mut changed);
    let changed_digest = verify_signed_update_metadata_v2(&changed, &trust, 100)
        .unwrap()
        .target_manifest_digest();
    assert_ne!(original, changed_digest);
}

#[test]
fn absent_descriptor_preserves_v2_golden_bytes() {
    let bytes = include_bytes!("../../../tests/fixtures/signed_installed_release_v2.json");
    let metadata: UpdateMetadataV2 = serde_json::from_slice(bytes).unwrap();
    assert!(
        metadata
            .targets
            .target
            .qualification_bootstrap_client_v1
            .is_none()
    );
    assert_eq!(serde_json::to_vec(&metadata).unwrap(), bytes);
}
