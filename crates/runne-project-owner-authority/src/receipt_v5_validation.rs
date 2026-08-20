//! Closed structural and lineage validation for root-signed receipt `/5`.

use std::collections::BTreeSet;

use crate::{
    AuthorityError, DelegationV2, PromotionAuthorityReceiptV5, V5_EVIDENCE_ROLE_SCOPES,
    V5_TRANSITION_ROLES, key_id, trust_canonical::hex,
};

pub fn validate(
    value: &PromotionAuthorityReceiptV5,
    trust: &crate::ProjectOwnerTrustConfigV4,
    predecessor: &crate::v5_lineage::V4LineageView<'_>,
) -> Result<(), AuthorityError> {
    if value.schema_version != crate::RECEIPT_SCHEMA_V5
        || value.repository_id != "gocode"
        || value.role != "PROJECT_OWNER"
        || value.purpose != crate::PURPOSE_V5
        || value.profile != crate::PROFILE_V5
        || value.trust_config_sha256 != hex(&trust.sha256()?)
        || value.trust_generation != trust.epoch
        || value.predecessor_receipt_sha256 != predecessor.receipt_sha256
        || value.platform_qualified_subject_sha256 != predecessor.bindings.subject_sha256()
        || value.platform_matrix_sha256 != predecessor.bindings.matrix_sha256()
        || value.promotion_policy_sha256 != predecessor.bindings.policy_sha256()
        || value.promotion_policy_revision != predecessor.bindings.policy_revision()
        || value.adr_0029_sha256 != crate::receipt_v5_document_profile::ADR_0029_SHA256
        || value.post_rc0_program_sha256 != crate::receipt_v5_document_profile::PROGRAM_SHA256
        || &value.subject != predecessor.subject
        || hex(&trust.predecessor) != predecessor.admission_scope.trust_config_sha256()
        || value.key_id != hex(&key_id(&trust.public_key))
        || value.key_epoch != trust.epoch
        || value.revocation_epoch == 0
        || !ordered(&value.issued_at, &value.not_before, &value.expires_at)
        || [
            &value.authority_store_profile,
            &value.root_principal_id,
            &value.root_controlling_account_id,
            &value.root_lane_id,
            &value.root_signature_profile_id,
        ]
        .iter()
        .any(|item| !crate::receipt_v4_validation::safe_id(item))
    {
        return Err(AuthorityError::InvalidReceiptTrust);
    }
    validate_delegations(value, trust.public_key)
}

/// Return the exact closed payload-schema set for one transition role or evidence scope.
#[must_use]
pub fn allowed_payload_schemas(role: &str, scope: &str) -> Vec<String> {
    let schemas: &[&str] = match (role, scope) {
        ("RC1_QUALIFICATION_AUTHORIZER", _) => &["gocode.release.rc1-qualification-decision/1"],
        ("RC2_SIGNING_AUTHORIZER", _) => &["gocode.release.rc2-signing-authorization/1"],
        ("RC3_PUBLICATION_AUTHORIZER", _) => &["gocode.release.rc3-publication-authorization/2"],
        ("RC2_NATIVE_EVIDENCE", "linux" | "windows") => &["gocode.release.rc2-native-evidence/1"],
        ("RC2_SIGNING_REVIEWER", "signing-review") => &["gocode.release.rc2-signing-review/1"],
        ("RC2_UPDATE_ISSUER", "update-issuer") => {
            &["gocode.release.rc2-update-metadata-issuance/1"]
        }
        ("RC3_FINAL_REVIEWER", "final-review") => &["gocode.release.rc3-final-review/1"],
        _ => &[],
    };
    schemas.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_delegations(
    value: &PromotionAuthorityReceiptV5,
    root: [u8; 32],
) -> Result<(), AuthorityError> {
    if value
        .transition_delegations
        .iter()
        .map(|item| item.role.as_str())
        .collect::<Vec<_>>()
        != V5_TRANSITION_ROLES
        || value
            .evidence_delegations
            .iter()
            .map(|item| (item.role.as_str(), item.scope.as_str()))
            .collect::<Vec<_>>()
            != V5_EVIDENCE_ROLE_SCOPES
    {
        return Err(AuthorityError::InvalidDelegation);
    }
    let mut identities = [
        BTreeSet::from([value.root_principal_id.as_str()]),
        BTreeSet::from([value.root_controlling_account_id.as_str()]),
        BTreeSet::from([value.root_lane_id.as_str()]),
        BTreeSet::from([value.key_id.as_str()]),
        BTreeSet::from([value.root_signature_profile_id.as_str()]),
    ];
    let mut public = BTreeSet::from([root]);
    for item in value
        .transition_delegations
        .iter()
        .chain(&value.evidence_delegations)
    {
        validate_delegation(item, value, &mut identities, &mut public)?;
    }
    Ok(())
}

fn validate_delegation<'a>(
    item: &'a DelegationV2,
    value: &'a PromotionAuthorityReceiptV5,
    identities: &mut [BTreeSet<&'a str>; 5],
    public: &mut BTreeSet<[u8; 32]>,
) -> Result<(), AuthorityError> {
    let identity = [
        item.principal_id.as_str(),
        item.controlling_account_id.as_str(),
        item.lane_id.as_str(),
        item.key_id.as_str(),
        item.signature_profile_id.as_str(),
    ];
    if item.scope.is_empty()
        || item.key_epoch == 0
        || item.revocation_epoch != value.revocation_epoch
        || item.key_id != hex(&key_id(&item.public_key))
        || !public.insert(item.public_key)
        || item.allowed_payload_schema_ids != allowed_payload_schemas(&item.role, &item.scope)
        || !ordered(&value.not_before, &item.not_before, &item.expires_at)
        || item.expires_at > value.expires_at
        || identity
            .iter()
            .any(|item| !crate::receipt_v4_validation::safe_id(item))
        || identity
            .iter()
            .enumerate()
            .any(|(index, item)| !identities[index].insert(item))
    {
        return Err(AuthorityError::InvalidDelegation);
    }
    Ok(())
}

fn ordered(a: &str, b: &str, c: &str) -> bool {
    crate::receipt_validation::valid_timestamp(a)
        && crate::receipt_validation::valid_timestamp(b)
        && crate::receipt_validation::valid_timestamp(c)
        && a < b
        && b < c
}
