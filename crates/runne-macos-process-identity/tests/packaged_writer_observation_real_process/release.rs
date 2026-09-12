use ed25519_dalek::{Signer as _, SigningKey};
use runne_api::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2, UpdateMetadataV2,
    UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2,
    UpdateTimestampRoleV2, UpdateTrustRootV2, VerifiedSignedInstalledReleaseV2,
    update_metadata_signing_bytes, verify_exact_signed_installed_release_v2,
    verify_signed_update_metadata_v2,
};

use super::package::{PackageRole, PackageView};

const NOW: u64 = 100;

pub struct ReleaseFixture {
    canonical: Vec<u8>,
    trust: UpdateTrustRootV2,
    binding: [u8; 32],
    writer_digest: [u8; 32],
    daemon_digest: [u8; 32],
}

impl ReleaseFixture {
    pub fn for_package(package: &PackageView) -> Self {
        let desktop_digest = package.digest(PackageRole::Desktop);
        let writer_digest = package.digest(PackageRole::Writer);
        let daemon_digest = package.digest(PackageRole::Daemon);
        let contract_digest = package.digest(PackageRole::Contract);
        let identities = [
            package.code_identity(PackageRole::Desktop),
            package.code_identity(PackageRole::Writer),
            package.code_identity(PackageRole::Daemon),
        ];
        let mut target = target(contract_digest);
        let tuple = NativeEnrollmentTupleV2::new_macos(
            target.release_candidate_sha256.clone(),
            encode_hex(&desktop_digest),
            encode_hex(&writer_digest),
            encode_hex(&daemon_digest),
            encode_hex(&contract_digest),
            identities[0].identifier.clone(),
            identities[0].team_identifier.clone(),
            identities[0].cdhash.clone(),
            identities[1].identifier.clone(),
            identities[1].team_identifier.clone(),
            identities[1].cdhash.clone(),
            identities[2].identifier.clone(),
            identities[2].team_identifier.clone(),
            identities[2].cdhash.clone(),
            &target,
        )
        .expect("build exact macOS tuple");
        let qualification = NativeEnrollmentQualificationRowV1::new(
            &target,
            &tuple,
            encode_hex(&[0x99; 32]),
            99,
            200,
        )
        .expect("build signed qualification");
        target.native_enrollment_tuple = Some(
            tuple
                .with_qualification(&target, qualification)
                .expect("bind signed qualification"),
        );
        let (metadata, trust) = signed_metadata(target);
        let canonical = serde_json::to_vec(&metadata).expect("canonical metadata");
        let binding = verify_signed_update_metadata_v2(&metadata, &trust, NOW)
            .expect("threshold-signed metadata")
            .qualified_release_candidate()
            .expect("qualified exact release")
            .release_binding_digest();
        Self {
            canonical,
            trust,
            binding,
            writer_digest,
            daemon_digest,
        }
    }

    pub fn verified_exact(&self) -> VerifiedSignedInstalledReleaseV2 {
        verify_exact_signed_installed_release_v2(&self.canonical, &self.trust, self.binding, NOW)
            .expect("verify exact installed release")
    }

    pub fn frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(12 + self.canonical.len());
        frame.extend_from_slice(b"GCRMDV2\0");
        frame.extend_from_slice(
            &u32::try_from(self.canonical.len())
                .expect("bounded metadata length")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&self.canonical);
        frame
    }

    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub const fn writer_digest(&self) -> [u8; 32] {
        self.writer_digest
    }

    pub const fn daemon_digest(&self) -> [u8; 32] {
        self.daemon_digest
    }
}

fn target(contract_digest: [u8; 32]) -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "runne".into(),
        version: "1.0.0".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        artifact_sha256: encode_hex(&[0xa1; 32]),
        artifact_size: 1,
        artifact_url: "https://updates.example.test/runne.dmg".into(),
        release_candidate_sha256: encode_hex(&[0xa2; 32]),
        min_os: "13.0".into(),
        profile_id: "protected-bundled".into(),
        bundle_sha256: encode_hex(&contract_digest),
        runtime_version: "1.0.0".into(),
        runtime_digest: encode_hex(&[0xa3; 32]),
        channel: "stable".into(),
        published_at_unix_seconds: 90,
        expires_at_unix_seconds: 300,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    }
}

fn signed_metadata(target: UpdateTargetV2) -> (UpdateMetadataV2, UpdateTrustRootV2) {
    let roots = signing_keys([31, 32, 33]);
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
    let root = UpdateRootRoleV2::from_trust(&trust, 7);
    let targets = UpdateTargetsRoleV2 {
        version: 8,
        expires_at_unix_seconds: 300,
        target,
    };
    let snapshot_role = UpdateSnapshotRoleV2 {
        version: 9,
        expires_at_unix_seconds: 300,
        targets_version: 8,
    };
    let timestamp_role = UpdateTimestampRoleV2 {
        version: 10,
        expires_at_unix_seconds: 300,
        snapshot_version: 9,
    };
    let metadata = UpdateMetadataV2 {
        schema_version: 2,
        root: root.clone(),
        targets: targets.clone(),
        snapshot: snapshot_role.clone(),
        timestamp: timestamp_role.clone(),
        root_signatures: signatures(&roots, &root),
        targets_signatures: signatures(&roots, &targets),
        snapshot_signature: sign(&snapshot, &snapshot_role),
        timestamp_signature: sign(&timestamp, &timestamp_role),
    };
    (metadata, trust)
}

fn signing_keys(bytes: [u8; 3]) -> [SigningKey; 3] {
    bytes.map(|byte| SigningKey::from_bytes(&[byte; 32]))
}

fn signatures<T: serde::Serialize>(keys: &[SigningKey; 3], value: &T) -> Vec<UpdateSignatureV2> {
    ["root-a", "root-b"]
        .into_iter()
        .zip(keys)
        .map(|(key_id, key)| UpdateSignatureV2 {
            key_id: key_id.into(),
            signature: sign(key, value),
        })
        .collect()
}

fn sign(key: &SigningKey, value: &impl serde::Serialize) -> String {
    let bytes = update_metadata_signing_bytes(value).expect("bounded signing bytes");
    encode_hex(&key.sign(&bytes).to_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
