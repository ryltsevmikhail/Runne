use ed25519_dalek::{Signer, SigningKey};

use super::super::*;

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn identity(identifier: &str, cdhash: char) -> MacOsCodeIdentityExpectationV1 {
    MacOsCodeIdentityExpectationV1::new(
        identifier,
        "758F9Z45SR",
        cdhash.to_string().repeat(40),
    )
    .unwrap()
}

fn verified(
    application_id_group: &str,
    protocols: NativeEnrollmentTupleV3ProtocolVersions,
    service_cdhash: char,
) -> VerifiedSignedNativeEnrollmentTupleV3 {
    let roots = [
        SigningKey::from_bytes(&[31; 32]),
        SigningKey::from_bytes(&[32; 32]),
        SigningKey::from_bytes(&[33; 32]),
    ];
    let timestamp = SigningKey::from_bytes(&[34; 32]);
    let snapshot = SigningKey::from_bytes(&[35; 32]);
    let trust = UpdateTrustRootV2::from_keys(
        [
            ("root-a", roots[0].verifying_key().to_bytes()),
            ("root-b", roots[1].verifying_key().to_bytes()),
            ("root-c", roots[2].verifying_key().to_bytes()),
        ],
        ("timestamp", timestamp.verifying_key().to_bytes()),
        ("snapshot", snapshot.verifying_key().to_bytes()),
    );
    let mut target = target();
    let tuple = NativeEnrollmentTupleV3::new(
        NativeEnrollmentTupleV3Digests {
            candidate_sha256: target.release_candidate_sha256.clone(),
            desktop_sha256: hash('1'),
            writer_sha256: hash('2'),
            daemon_sha256: hash('3'),
            credential_service_sha256: hash('4'),
            launch_agent_plist_sha256: hash('5'),
            entitlements_sha256: hash('6'),
            provisioning_sha256: hash('7'),
            xpc_protocol_sha256: hash('8'),
            contract_sha256: target.bundle_sha256.clone(),
        },
        NativeEnrollmentTupleV3Deployment::for_application_id_group(
            application_id_group,
            protocols,
        ),
        NativeEnrollmentTupleV3CodeIdentities::new(
            identity("com.runne.desktop", '1'),
            identity("runne", '2'),
            identity("runned", '3'),
            identity("com.runne.credential-service", service_cdhash),
        ),
        &target,
    )
    .unwrap();
    target.native_enrollment_tuple_v3 = Some(tuple);
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: 500,
        target,
    };
    let snapshot_role = UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: 500,
        targets_version: 8,
    };
    let timestamp_role = UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: 500,
        snapshot_version: 9,
    };
    let metadata = UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: vec![
            signature("root-a", &roots[0], &root),
            signature("root-b", &roots[1], &root),
        ],
        targets_signatures: vec![
            signature("root-a", &roots[0], &targets),
            signature("root-b", &roots[1], &targets),
        ],
        snapshot_signature: sign(&snapshot, &snapshot_role),
        timestamp_signature: sign(&timestamp, &timestamp_role),
    };
    let binding = UpdateTargetV2Binding {
        product_id: "com.runne.desktop",
        platform: "macos",
        arch: "arm64",
        min_os: "13.0",
        profile_id: "gocode-ui-client/2",
        bundle_sha256: &metadata.targets.target.bundle_sha256,
        runtime_version: "0.1.0",
        runtime_digest: &metadata.targets.target.runtime_digest,
        channel: "stable",
    };
    verify_update_v2(&metadata, &trust, &binding, 100, "1.0.0", "1.0.0")
        .unwrap()
        .native_enrollment_tuple_v3()
        .unwrap()
        .clone()
}

fn protocol(
    registration_auth_suite: u16,
    provider_frame_wire: u16,
    provider_grant_auth: u16,
    runtime_envelope_wire: u16,
    runtime_request_auth: u16,
    runtime_reply_auth: u16,
) -> NativeEnrollmentTupleV3ProtocolCompatibility {
    NativeEnrollmentTupleV3ProtocolCompatibility::new(
        1,
        registration_auth_suite,
        provider_frame_wire,
        provider_grant_auth,
        runtime_envelope_wire,
        runtime_request_auth,
        runtime_reply_auth,
    )
}

fn protocols(
    bundles: impl IntoIterator<Item = NativeEnrollmentTupleV3ProtocolCompatibility>,
) -> NativeEnrollmentTupleV3ProtocolVersions {
    NativeEnrollmentTupleV3ProtocolVersions::new(bundles.into_iter().collect())
}

#[test]
fn updater_requires_reconciliation_before_compatible_v3_rotation() {
    let current = verified(
        "758F9Z45SR.com.runne.credential-service",
        protocols([protocol(1, 2, 1, 2, 3, 3)]),
        '4',
    );
    let next = verified(
        "758F9Z45SR.com.runne.credential-service",
        protocols([
            protocol(1, 2, 1, 2, 3, 3),
            protocol(2, 3, 2, 3, 4, 4),
        ]),
        '5',
    );
    assert_eq!(
        evaluate_native_enrollment_tuple_v3_update(
            &current,
            &next,
            NativeEnrollmentTupleV3EffectState::Reconciled,
        ),
        Ok(NativeEnrollmentTupleV3UpdateDisposition::Ready)
    );
    for state in [
        NativeEnrollmentTupleV3EffectState::Armed,
        NativeEnrollmentTupleV3EffectState::Uncertain,
    ] {
        assert_eq!(
            evaluate_native_enrollment_tuple_v3_update(&current, &next, state),
            Ok(NativeEnrollmentTupleV3UpdateDisposition::ReconciliationRequired)
        );
    }
}

#[test]
fn updater_rejects_application_id_group_change_and_no_protocol_overlap() {
    let current = verified(
        "758F9Z45SR.com.runne.credential-service",
        protocols([protocol(1, 2, 1, 2, 3, 3)]),
        '4',
    );
    let moved = verified(
        "758F9Z45SR.com.runne.credential-service.v2",
        protocols([protocol(1, 2, 1, 2, 3, 3)]),
        '5',
    );
    assert_eq!(
        evaluate_native_enrollment_tuple_v3_update(
            &current,
            &moved,
            NativeEnrollmentTupleV3EffectState::Reconciled,
        ),
        Err(NativeEnrollmentTupleV3UpdateError::UnsupportedApplicationIdGroupChange)
    );
    let incompatible = verified(
        "758F9Z45SR.com.runne.credential-service",
        protocols([protocol(1, 3, 1, 3, 3, 3)]),
        '5',
    );
    assert_eq!(
        evaluate_native_enrollment_tuple_v3_update(
            &current,
            &incompatible,
            NativeEnrollmentTupleV3EffectState::Reconciled,
        ),
        Err(NativeEnrollmentTupleV3UpdateError::UnsupportedProtocolTransition)
    );
}

#[test]
fn updater_rejects_same_wire_versions_with_incompatible_auth_semantics() {
    let current = verified(
        "758F9Z45SR.com.runne.credential-service",
        protocols([protocol(1, 2, 1, 2, 3, 3)]),
        '4',
    );
    for incompatible in [
        protocol(2, 2, 1, 2, 3, 3),
        protocol(1, 2, 2, 2, 3, 3),
        protocol(1, 2, 1, 2, 4, 3),
        protocol(1, 2, 1, 2, 3, 4),
    ] {
        let next = verified(
            "758F9Z45SR.com.runne.credential-service",
            protocols([incompatible]),
            '5',
        );
        assert_eq!(
            evaluate_native_enrollment_tuple_v3_update(
                &current,
                &next,
                NativeEnrollmentTupleV3EffectState::Reconciled,
            ),
            Err(NativeEnrollmentTupleV3UpdateError::UnsupportedProtocolTransition)
        );
    }
}

fn target() -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "com.runne.desktop".into(), version: "1.2.3".into(),
        platform: "macos".into(), arch: "arm64".into(), artifact_sha256: hash('a'),
        artifact_size: 10, artifact_url: "https://updates.example.test/Runne.dmg".into(),
        release_candidate_sha256: hash('0'), min_os: "13.0".into(),
        profile_id: "gocode-ui-client/2".into(), bundle_sha256: hash('9'),
        runtime_version: "0.1.0".into(), runtime_digest: hash('b'), channel: "stable".into(),
        published_at_unix_seconds: 100, expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(), native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
    }
}

fn sign(key: &SigningKey, value: &impl serde::Serialize) -> String {
    hex::encode(key.sign(&serde_json::to_vec(value).unwrap()).to_bytes())
}

fn signature(
    key_id: &str,
    key: &SigningKey,
    value: &impl serde::Serialize,
) -> UpdateSignatureV2 {
    UpdateSignatureV2 { key_id: key_id.into(), signature: sign(key, value) }
}
