//! Closed V4 bootstrap validator adversarial vectors.
use crate::{
    DelegationV1, Document, GitSubject, PromotionBootstrapV4, key_id,
    receipt_v4_profile::{DOCUMENTS, PinnedDocument},
    receipt_v4_validation::{allowed, validate_bootstrap},
    trust_canonical::hex,
};
use ed25519_dalek::SigningKey;
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
use sha2::{Digest as _, Sha256};

fn bootstrap() -> (PromotionBootstrapV4, [u8; 32]) {
    let root = SigningKey::from_bytes(&[1; 32]);
    let root_key = root.verifying_key().to_bytes();
    let roles = [
        ("RC1_QUALIFICATION_AUTHORIZER", 2_u8),
        ("RC2_SIGNING_AUTHORIZER", 3),
        ("RC3_PUBLICATION_AUTHORIZER", 4),
    ];
    let delegations = roles
        .into_iter()
        .enumerate()
        .map(|(index, (role, seed))| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let public_key = key.verifying_key().to_bytes();
            DelegationV1 {
                role: role.into(),
                principal_id: format!("principal-{}", index + 1),
                controlling_account_id: format!("account-{}", index + 1),
                lane_id: format!("lane-{}", index + 1),
                key_id: hex(&key_id(&public_key)),
                public_key,
                key_epoch: 1,
                signature_profile_id: format!("profile-{}", index + 1),
                not_before: "2026-08-13T00:00:02Z".into(),
                expires_at: "2026-08-13T00:00:03Z".into(),
                revocation_epoch: 1,
                allowed_payload_schema_ids: allowed(role),
            }
        })
        .collect();
    let documents = DOCUMENTS.into_iter().map(document).collect();
    (
        PromotionBootstrapV4 {
            schema_version: "gocode.project-owner.authority-receipt/4".into(),
            repository_id: "gocode".into(),
            role: "PROJECT_OWNER".into(),
            purpose: "POST_RC0_PROMOTION_AUTHORITY_BOOTSTRAP".into(),
            profile: "gocode.project-owner.post-rc0-promotion/1".into(),
            predecessor_receipt_sha256: [1; 32],
            platform_qualified_subject_sha256: [2; 32],
            platform_matrix_sha256: [3; 32],
            promotion_policy_sha256: [4; 32],
            promotion_policy_revision: "policy-1".into(),
            authority_store_profile: "store-1".into(),
            root_principal_id: "root-principal".into(),
            root_controlling_account_id: "root-account".into(),
            root_lane_id: "root-lane".into(),
            root_signature_profile_id: "root-profile".into(),
            issued_at: "2026-08-13T00:00:00Z".into(),
            not_before: "2026-08-13T00:00:01Z".into(),
            expires_at: "2026-08-13T00:00:04Z".into(),
            revocation_epoch: 1,
            delegations,
            subject: GitSubject {
                object_format: "sha1".into(),
                commit_oid: "c".repeat(40),
                tree_oid: "d".repeat(40),
            },
            documents,
            trust_config_sha256: "e".repeat(64),
            key_id: hex(&key_id(&root_key)),
            key_epoch: 3,
        },
        root_key,
    )
}

fn document(value: PinnedDocument) -> Document {
    Document {
        path: value.path.into(),
        mode: value.mode.into(),
        blob_oid: value.blob_oid.into(),
        content_sha256: value.content_sha256.into(),
        byte_length: value.byte_length,
        schema_id: value.schema_id.map(str::to_owned),
    }
}

#[test]
#[ignore = "requires unpublished historical source documents"]
fn promotion_document_profile_matches_authoritative_raw_files() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for expected in DOCUMENTS {
        let path = root.join(expected.path);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "requires original unpublished historical source {}: {error}",
                path.display()
            )
        });
        let content_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(bytes.len() as u64, expected.byte_length);
        assert_eq!(hex(&content_sha256), expected.content_sha256);
        assert_eq!(git_blob_sha1(&bytes), expected.blob_oid);
        assert_eq!(expected.mode, "100644");
        assert_eq!(expected.schema_id, None);
    }
}

fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut source = format!("blob {}\0", bytes.len()).into_bytes();
    source.extend_from_slice(bytes);
    ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, &source)
        .as_ref()
        .iter()
        .flat_map(|byte| [nibble(byte >> 4), nibble(byte & 0x0f)])
        .collect()
}

const fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

#[test]
fn bootstrap_validator_rejects_exact_closed_contract_mutations() {
    let (value, root) = bootstrap();
    validate_bootstrap(&value, root).unwrap();
    let mutations: [fn(&mut PromotionBootstrapV4); 20] = [
        |v| v.subject.object_format = "sha256".into(),
        |v| v.documents.reverse(),
        |v| v.documents[0].mode = "100755".into(),
        |v| v.documents[0].schema_id = Some("gocode.unexpected/1".into()),
        |v| v.promotion_policy_revision = "unsafe/slash".into(),
        |v| v.authority_store_profile = "unsafe/slash".into(),
        |v| v.key_epoch = 2,
        |v| v.revocation_epoch = 0,
        |v| v.root_principal_id = "-leading-punctuation".into(),
        |v| v.expires_at = v.not_before.clone(),
        |v| v.delegations.reverse(),
        |v| v.delegations[1].principal_id = v.delegations[0].principal_id.clone(),
        |v| {
            v.delegations[1].controlling_account_id =
                v.delegations[0].controlling_account_id.clone();
        },
        |v| v.delegations[1].lane_id = v.delegations[0].lane_id.clone(),
        |v| v.delegations[1].key_id = v.delegations[0].key_id.clone(),
        |v| v.delegations[1].public_key = v.delegations[0].public_key,
        |v| v.delegations[1].allowed_payload_schema_ids = vec![],
        |v| v.documents[0].blob_oid = "c".repeat(40),
        |v| v.documents[0].content_sha256 = "d".repeat(64),
        |v| v.documents[0].byte_length = 2,
    ];
    for mutate in mutations {
        let mut changed = value.clone();
        mutate(&mut changed);
        assert!(validate_bootstrap(&changed, root).is_err());
    }
    let mut root_reuse = value;
    root_reuse.delegations[0].public_key = root;
    root_reuse.delegations[0].key_id = hex(&key_id(&root));
    assert!(validate_bootstrap(&root_reuse, root).is_err());
    let (mut root_identity_reuse, root) = bootstrap();
    root_identity_reuse.root_principal_id = root_identity_reuse.delegations[0].principal_id.clone();
    assert!(validate_bootstrap(&root_identity_reuse, root).is_err());
}
