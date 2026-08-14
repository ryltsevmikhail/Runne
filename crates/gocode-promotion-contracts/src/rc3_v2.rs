use sha2::{Digest as _, Sha256};

use crate::rc3_v2_facts::Facts;
use crate::rc3_v2_models::{
    Authorization, FinalReview, HumanArtifacts, Identity, Manifest, PublicArtifact,
};
use crate::{ContractError, canonical_id, digests};

/// Closed neutral RC3 v2 leaf payload kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    /// Immutable public publication manifest.
    PublicationManifest,
    /// Final-review evidence payload.
    FinalReview,
    /// Publication authorization payload.
    Authorization,
}

/// Structurally validated canonical RC3 v2 leaf bytes with no authority capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPayload {
    kind: PayloadKind,
    canonical: Vec<u8>,
    sha256: [u8; 32],
    facts: Facts,
}

impl ValidatedPayload {
    /// Return the closed structural leaf kind.
    #[must_use]
    pub const fn kind(&self) -> PayloadKind {
        self.kind
    }
    /// Return the SHA-256 of exact LF-excluded canonical bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    /// Return exact canonical bytes with no envelope line feed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.canonical
    }
    /// Return identities available for downstream separation checks.
    #[must_use]
    pub const fn facts(&self) -> &Facts {
        &self.facts
    }
}

/// Validate exact LF-excluded canonical bytes for an RC3 v2 leaf contract.
///
/// # Errors
/// Returns an error for an unknown schema, malformed input, or failed structural invariant.
pub fn validate(schema_id: &str, canonical: &[u8]) -> Result<ValidatedPayload, ContractError> {
    let kind = match schema_id {
        "gocode.release.publication-manifest/2" => PayloadKind::PublicationManifest,
        "gocode.release.rc3-final-review/1" => PayloadKind::FinalReview,
        "gocode.release.rc3-publication-authorization/2" => PayloadKind::Authorization,
        _ => return Err(ContractError::InvalidCanonicalPayload),
    };
    let value = crate::strict_json::parse(canonical)
        .map_err(|()| ContractError::InvalidCanonicalPayload)?;
    let (valid, facts) = match kind {
        PayloadKind::PublicationManifest => serde_json::from_value::<Manifest>(value.clone())
            .map(|x| (manifest(&x), crate::rc3_v2_facts::manifest(&x))),
        PayloadKind::FinalReview => serde_json::from_value::<FinalReview>(value.clone())
            .map(|x| (final_review(&x), crate::rc3_v2_facts::review(&x))),
        PayloadKind::Authorization => serde_json::from_value::<Authorization>(value.clone())
            .map(|x| (authorization(&x), crate::rc3_v2_facts::authorization(&x))),
    }
    .map_err(|_| ContractError::InvalidCanonicalPayload)?;
    if !valid || serde_json::to_vec(&crate::sorted(value)).ok().as_deref() != Some(canonical) {
        return Err(ContractError::InvalidCanonicalPayload);
    }
    Ok(ValidatedPayload {
        kind,
        canonical: canonical.to_vec(),
        sha256: Sha256::digest(canonical).into(),
        facts,
    })
}

fn manifest(value: &Manifest) -> bool {
    value.schema_version == "gocode.release.publication-manifest/2"
        && value.release_sequence > 0
        && value.macos_preview_excluded
        && nonempty(&value.app_version)
        && ids(&[
            &value.bundle_identity,
            &value.channel_policy_id,
            &value.channel,
        ])
        && destination(&value.destination)
        && exact_public_artifacts(&value.public_artifacts)
        && human_artifacts(&value.human_artifacts)
        && digests(&[
            &value.candidate_sha256,
            &value.inventory_sha256,
            &value.report_sha256,
            &value.metadata_set_sha256,
            &value.rollback_policy_sha256,
            &value.rollout_policy_sha256,
            &value.effect_scope_sha256,
        ])
}

fn final_review(value: &FinalReview) -> bool {
    value.schema_version == "gocode.release.rc3-final-review/1"
        && value.decision == "approved"
        && valid_window(value.valid_from, value.expires_at, value.revocation_epoch)
        && value.allowlist_generation > 0
        && destination(&value.destination)
        && canonical_id(&value.channel)
        && identity(&value.reviewer)
        && human_artifacts(&value.human_artifacts)
        && digests(&[
            &value.candidate_sha256,
            &value.publication_manifest_sha256,
            &value.inventory_sha256,
            &value.report_sha256,
            &value.metadata_set_sha256,
            &value.allowlist_sha256,
            &value.effect_scope_sha256,
        ])
}

fn authorization(value: &Authorization) -> bool {
    value.schema_version == "gocode.release.rc3-publication-authorization/2"
        && !value.self_execution
        && valid_window(value.valid_from, value.expires_at, value.revocation_epoch)
        && value.allowlist_generation > 0
        && destination(&value.destination)
        && ids(&[&value.channel, &value.idempotency_namespace])
        && identity(&value.authorizer)
        && identity(&value.executor)
        && disjoint(&value.authorizer, &value.executor)
        && digests(&[
            &value.candidate_sha256,
            &value.publication_manifest_sha256,
            &value.final_review_sha256,
            &value.allowlist_sha256,
            &value.inventory_sha256,
            &value.report_sha256,
            &value.metadata_set_sha256,
            &value.effect_scope_sha256,
            &value.executable_sha256,
            &value.workflow_sha256,
            &value.self_execution_policy_sha256,
        ])
}

fn exact_public_artifacts(value: &[PublicArtifact]) -> bool {
    matches!(value, [appimage, deb, windows]
        if appimage.artifact_slot_id == "linux-appimage"
            && appimage.platform == "linux"
            && deb.artifact_slot_id == "linux-deb"
            && deb.platform == "linux"
            && windows.artifact_slot_id == "windows-installer-unsigned"
            && windows.platform == "windows")
        && value.iter().all(|artifact| {
            canonical_id(&artifact.architecture)
                && artifact.byte_length > 0
                && digests(&[&artifact.artifact_sha256, &artifact.checksum_sha256])
                && artifact.artifact_sha256 != artifact.checksum_sha256
        })
}

fn human_artifacts(value: &HumanArtifacts) -> bool {
    let values = [
        value.release_notes.as_str(),
        value.changelog.as_str(),
        value.compatibility_support.as_str(),
        value.provenance.as_str(),
        value.sbom.as_str(),
        value.checksums.as_str(),
    ];
    digests(&values)
        && values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == values.len()
}

const fn valid_window(valid_from: u64, expires_at: u64, revocation_epoch: u64) -> bool {
    valid_from < expires_at && revocation_epoch > 0
}

fn identity(value: &Identity) -> bool {
    ids(&[
        &value.principal,
        &value.account,
        &value.lane,
        &value.signature_profile,
    ]) && digests(&[&value.key])
}

fn disjoint(left: &Identity, right: &Identity) -> bool {
    left.principal != right.principal
        && left.account != right.account
        && left.lane != right.lane
        && left.key != right.key
        && left.signature_profile != right.signature_profile
}

fn ids(values: &[&str]) -> bool {
    values.iter().all(|value| canonical_id(value))
}

fn destination(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

const fn nonempty(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}
