use std::cell::Cell;

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::{
    DelegationV2, GitSubject, PromotionAuthorityReceiptV5, V5_EVIDENCE_ROLE_SCOPES,
    V5_TRANSITION_ROLES, VerifiedPromotionBootstrapV5, canonical_checked_in_receipt_v5,
    canonical_config_v4, trust_canonical::hex, verify_promotion_authority_receipt_v5,
};

pub struct Chain {
    pub root: SigningKey,
    pub trust: crate::VerifiedTrustConfigV4,
    pub receipt5: VerifiedPromotionBootstrapV5,
}

pub fn chain() -> Chain {
    let root = SigningKey::from_bytes(&[3; 32]);
    let trust = trust(&root, [1; 32]);
    let predecessor = predecessor(&subject(), hex(&[1; 32]));
    let receipt = receipt(&trust);
    let bytes = signed_bytes(&root, &receipt);
    let receipt5 = verify_promotion_authority_receipt_v5(
        &bytes,
        Sha256::digest(&bytes).into(),
        &trust,
        &predecessor,
        &crate::ExpectedReceiptV5Bindings::test_only(
            receipt.production_security_review_sha256,
            receipt.subject.clone(),
            receipt.destination_allowlist_sha256,
            receipt.destination_allowlist_generation,
        ),
        &super::Receipt5Context(Cell::new(0)),
    )
    .expect("deterministic receipt/5 fixture must verify");
    Chain {
        root,
        trust,
        receipt5,
    }
}

pub fn trust(root: &SigningKey, predecessor: [u8; 32]) -> crate::VerifiedTrustConfigV4 {
    let mut config = crate::ProjectOwnerTrustConfigV4 {
        schema_version: crate::trust_v4::CONFIG_SCHEMA_V4.into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        epoch: 4,
        key_id: crate::key_id(&root.verifying_key().to_bytes()),
        public_key: root.verifying_key().to_bytes(),
        schema_digests: crate::v4_trust_schema_digests().unwrap(),
        proof_of_possession: [0; 64],
        predecessor,
        predecessor_schema_version: "runne.project-owner.trust-config/3".into(),
    };
    config.proof_of_possession = root
        .sign(
            &crate::framed_transcript(
                crate::trust_v4::POP_DOMAIN_V4,
                &canonical_config_v4(&config, false).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    crate::trust_v4::verified_v4(config)
}

pub fn predecessor(
    subject: &GitSubject,
    trust_config_sha256: String,
) -> crate::VerifiedPromotionBootstrap {
    crate::receipt_v4::verified_bootstrap(
        [2; 32],
        Vec::new(),
        [4; 32],
        subject.clone(),
        trust_config_sha256,
    )
}

pub fn subject() -> GitSubject {
    GitSubject {
        object_format: "sha1".into(),
        commit_oid: "a".repeat(40),
        tree_oid: "b".repeat(40),
    }
}

pub fn receipt(config: &crate::ProjectOwnerTrustConfigV4) -> PromotionAuthorityReceiptV5 {
    let mut next = 10_u8;
    let mut delegation = |role: &str, scope: &str| {
        let key = SigningKey::from_bytes(&[next; 32]);
        next += 1;
        DelegationV2 {
            role: role.into(),
            scope: scope.into(),
            principal_id: format!("principal{next}"),
            controlling_account_id: format!("account{next}"),
            lane_id: format!("lane{next}"),
            key_id: hex(&crate::key_id(&key.verifying_key().to_bytes())),
            public_key: key.verifying_key().to_bytes(),
            key_epoch: 1,
            signature_profile_id: format!("profile{next}"),
            not_before: "2026-01-01T00:00:02Z".into(),
            expires_at: "2026-01-01T00:00:04Z".into(),
            revocation_epoch: 1,
            allowed_payload_schema_ids: crate::receipt_v5_validation::allowed_payload_schemas(
                role, scope,
            ),
        }
    };
    PromotionAuthorityReceiptV5 {
        schema_version: crate::RECEIPT_SCHEMA_V5.into(),
        repository_id: "runne".into(),
        role: "PROJECT_OWNER".into(),
        purpose: crate::PURPOSE_V5.into(),
        profile: crate::PROFILE_V5.into(),
        predecessor_receipt_sha256: [2; 32],
        trust_config_sha256: hex(&config.sha256().unwrap()),
        trust_generation: 4,
        platform_qualified_subject_sha256: [0; 32],
        platform_matrix_sha256: [0; 32],
        production_security_review_sha256:
            crate::receipt_v5_document_profile::PRODUCTION_SECURITY_REVIEW_SHA256,
        promotion_policy_sha256: [0; 32],
        promotion_policy_revision: String::new(),
        adr_0029_sha256: crate::receipt_v5_document_profile::ADR_0029_SHA256,
        post_rc0_program_sha256: crate::receipt_v5_document_profile::PROGRAM_SHA256,
        destination_allowlist_sha256:
            crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_SHA256,
        destination_allowlist_generation:
            crate::receipt_v5_document_profile::INITIAL_DESTINATION_ALLOWLIST_GENERATION,
        authority_store_profile: "store".into(),
        root_principal_id: "rootprincipal".into(),
        root_controlling_account_id: "rootaccount".into(),
        root_lane_id: "rootlane".into(),
        root_signature_profile_id: "rootprofile".into(),
        issued_at: "2026-01-01T00:00:00Z".into(),
        not_before: "2026-01-01T00:00:01Z".into(),
        expires_at: "2026-01-01T00:00:05Z".into(),
        revocation_epoch: 1,
        transition_delegations: V5_TRANSITION_ROLES
            .into_iter()
            .map(|role| delegation(role, "transition"))
            .collect(),
        evidence_delegations: V5_EVIDENCE_ROLE_SCOPES
            .into_iter()
            .map(|(role, scope)| delegation(role, scope))
            .collect(),
        subject: subject(),
        key_id: hex(&config.key_id),
        key_epoch: 4,
    }
}

pub fn signed_bytes(root: &SigningKey, receipt: &PromotionAuthorityReceiptV5) -> Vec<u8> {
    let signature = root
        .sign(
            &crate::framed_transcript(
                b"runne.project-owner.authority-receipt/5",
                &crate::canonical_unsigned_receipt_v5(receipt).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes();
    canonical_checked_in_receipt_v5(receipt, &signature).unwrap()
}
