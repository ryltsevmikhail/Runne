use serde::{Deserialize, Serialize};

use super::common::{HexDigest, identifier};
use crate::AuthorityError;

pub(super) const SNAPSHOT: &str = "gocode.release.promotion-state-snapshot/1";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub schema_version: String,
    pub promotion_id: String,
    pub revision: u64,
    pub state: String,
    pub candidate_binding_sha256: HexDigest,
    pub candidate_sha256: HexDigest,
    pub effect_generation: u64,
    pub previous_snapshot_sha256: HexDigest,
    pub command_fingerprint_sha256: HexDigest,
    pub domain: String,
}
pub(super) fn validate(value: &Snapshot) -> Result<(), AuthorityError> {
    if value.schema_version != SNAPSHOT
        || !matches!(
            value.state.as_str(),
            "rc0_ingested"
                | "rc1_review"
                | "qualified_unsigned"
                | "signing_authorized"
                | "signed_envelopes_verified"
                | "rc3_review"
                | "publication_authorized"
        )
        || !matches!(value.domain.as_str(), "fixture" | "production")
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    identifier(&value.promotion_id)
}
