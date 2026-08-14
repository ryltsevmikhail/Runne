use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub(super) schema_version: String,
    pub(super) candidate_sha256: String,
    pub(super) inventory_sha256: String,
    pub(super) report_sha256: String,
    pub(super) metadata_set_sha256: String,
    pub(super) public_artifacts: Vec<PublicArtifact>,
    pub(super) human_artifacts: HumanArtifacts,
    pub(super) app_version: String,
    pub(super) release_sequence: u64,
    pub(super) bundle_identity: String,
    pub(super) destination: String,
    pub(super) channel_policy_id: String,
    pub(super) channel: String,
    pub(super) rollback_policy_sha256: String,
    pub(super) rollout_policy_sha256: String,
    pub(super) effect_scope_sha256: String,
    pub(super) macos_preview_excluded: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicArtifact {
    pub(super) artifact_slot_id: String,
    pub(super) platform: String,
    pub(super) architecture: String,
    pub(super) artifact_sha256: String,
    pub(super) byte_length: u64,
    pub(super) checksum_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanArtifacts {
    pub(super) release_notes: String,
    pub(super) changelog: String,
    pub(super) compatibility_support: String,
    pub(super) provenance: String,
    pub(super) sbom: String,
    pub(super) checksums: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalReview {
    pub(super) schema_version: String,
    pub(super) candidate_sha256: String,
    pub(super) publication_manifest_sha256: String,
    pub(super) inventory_sha256: String,
    pub(super) report_sha256: String,
    pub(super) metadata_set_sha256: String,
    pub(super) human_artifacts: HumanArtifacts,
    pub(super) allowlist_sha256: String,
    pub(super) allowlist_generation: u64,
    pub(super) destination: String,
    pub(super) channel: String,
    pub(super) effect_scope_sha256: String,
    pub(super) reviewer: Identity,
    pub(super) valid_from: u64,
    pub(super) expires_at: u64,
    pub(super) revocation_epoch: u64,
    pub(super) decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub(super) schema_version: String,
    pub(super) candidate_sha256: String,
    pub(super) publication_manifest_sha256: String,
    pub(super) final_review_sha256: String,
    pub(super) allowlist_sha256: String,
    pub(super) allowlist_generation: u64,
    pub(super) inventory_sha256: String,
    pub(super) report_sha256: String,
    pub(super) metadata_set_sha256: String,
    pub(super) destination: String,
    pub(super) channel: String,
    pub(super) effect_scope_sha256: String,
    pub(super) authorizer: Identity,
    pub(super) executor: Identity,
    pub(super) executable_sha256: String,
    pub(super) workflow_sha256: String,
    pub(super) idempotency_namespace: String,
    pub(super) valid_from: u64,
    pub(super) expires_at: u64,
    pub(super) revocation_epoch: u64,
    pub(super) self_execution: bool,
    pub(super) self_execution_policy_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    #[serde(rename = "principal_id")]
    pub(super) principal: String,
    #[serde(rename = "account_id")]
    pub(super) account: String,
    #[serde(rename = "lane_id")]
    pub(super) lane: String,
    #[serde(rename = "key_id")]
    pub(super) key: String,
    #[serde(rename = "signature_profile_id")]
    pub(super) signature_profile: String,
}
