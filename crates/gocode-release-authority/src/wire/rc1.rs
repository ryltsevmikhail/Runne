use serde::{Deserialize, Serialize};

use super::{
    common::{HexDigest, identifier},
    rc1_facts::{self, ReleaseFacts},
};
use crate::AuthorityError;

pub(super) const RC1: &str = "gocode.release.rc1-qualification-decision/1";
pub(super) const MANIFEST: &str = "gocode.release.unsigned-candidate-manifest/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rc1Decision {
    pub schema_version: String,
    pub candidate_binding_sha256: HexDigest,
    pub subject_sha256: HexDigest,
    pub matrix_sha256: HexDigest,
    pub bootstrap_sha256: HexDigest,
    pub candidate_sha256: HexDigest,
    pub policy_sha256: HexDigest,
    pub release_facts_sha256: HexDigest,
    pub approver: Identity,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub disposition: String,
    pub signing_allowed: bool,
    pub publication_allowed: bool,
    pub external_effects: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnsignedManifest {
    pub schema_version: String,
    pub candidate_sha256: HexDigest,
    pub subject_sha256: HexDigest,
    pub matrix_sha256: HexDigest,
    pub bootstrap_sha256: HexDigest,
    pub policy_sha256: HexDigest,
    #[serde(flatten)]
    pub release_facts: ReleaseFacts,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    #[serde(rename = "principal_id")]
    pub principal: String,
    #[serde(rename = "account_id")]
    pub account: String,
    #[serde(rename = "lane_id")]
    pub lane: String,
    #[serde(rename = "key_id")]
    pub key: String,
    #[serde(rename = "signature_profile_id")]
    pub signature_profile: String,
}
pub(super) fn validate_decision(value: &Rc1Decision) -> Result<(), AuthorityError> {
    if value.schema_version != RC1
        || value.disposition != "qualified_unsigned"
        || value.signing_allowed
        || value.publication_allowed
        || !value.external_effects.is_empty()
        || value.valid_from >= value.expires_at
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    validate_identity(&value.approver)
}
pub(super) fn validate_manifest(value: &UnsignedManifest) -> Result<(), AuthorityError> {
    if value.schema_version != MANIFEST {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    rc1_facts::validate(&value.release_facts)
}
fn validate_identity(value: &Identity) -> Result<(), AuthorityError> {
    for item in [
        &value.principal,
        &value.account,
        &value.lane,
        &value.key,
        &value.signature_profile,
    ] {
        identifier(item)?;
    }
    Ok(())
}
