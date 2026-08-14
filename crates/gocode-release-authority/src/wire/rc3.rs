//! Legacy RC3 `/1` publication leaf parsers.
//!
//! These validators describe the superseded `/1` schema and exist only as legacy
//! audit inputs. The active wire decode rejects `/1` with `AuthorityVersionSuperseded`
//! before these validators run, so no `/1` payload can be admitted as active v2 authority.

use serde::{Deserialize, Serialize};

use super::common::{HexDigest, destination, identifier};
use crate::AuthorityError;

pub(super) const MANIFEST: &str = "gocode.release.publication-manifest/1";
pub(super) const AUTH: &str = "gocode.release.rc3-publication-authorization/1";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicationManifest {
    pub schema_version: String,
    pub candidate_sha256: HexDigest,
    pub inventory_sha256: HexDigest,
    pub report_sha256: HexDigest,
    pub metadata_set_sha256: HexDigest,
    pub human_artifact_sha256: Vec<HexDigest>,
    pub human_artifact_categories: Vec<String>,
    pub version: String,
    pub channel: String,
    pub destination: String,
    pub artifacts: Vec<String>,
    pub rollback_policy_sha256: HexDigest,
    pub rollout_policy_sha256: HexDigest,
    pub macos_preview_excluded: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicationAuthorization {
    pub schema_version: String,
    pub inventory_sha256: HexDigest,
    pub report_sha256: HexDigest,
    pub publication_manifest_sha256: HexDigest,
    pub executor_principal: String,
    pub lane: String,
    pub workflow_sha256: HexDigest,
    pub idempotency_namespace: String,
    pub destination: String,
    pub channel: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub no_effect: bool,
    pub external_effects: Vec<String>,
}
pub(super) fn manifest(value: &PublicationManifest) -> Result<(), AuthorityError> {
    if value.schema_version != MANIFEST
        || value.human_artifact_sha256.len() != 5
        || value.human_artifact_categories
            != [
                "release_notes",
                "changelog",
                "compatibility_support",
                "provenance",
                "sbom",
            ]
        || value.version.is_empty()
        || !matches!(value.channel.as_str(), "stable" | "beta" | "internal")
        || value.artifacts != ["linux", "windows"]
        || !value.macos_preview_excluded
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    destination(&value.destination)?;
    Ok(())
}
pub(super) fn auth(value: &PublicationAuthorization) -> Result<(), AuthorityError> {
    if value.schema_version != AUTH
        || value.valid_from >= value.expires_at
        || !value.no_effect
        || !value.external_effects.is_empty()
        || !matches!(value.channel.as_str(), "stable" | "beta" | "internal")
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    for item in [
        &value.executor_principal,
        &value.lane,
        &value.idempotency_namespace,
    ] {
        identifier(item)?;
    }
    destination(&value.destination)
}
