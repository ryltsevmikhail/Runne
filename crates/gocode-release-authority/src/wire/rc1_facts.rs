//! Closed immutable release facts carried by the unsigned RC1 candidate.

use serde::{Deserialize, Serialize};

use super::common::HexDigest;
use crate::AuthorityError;

const SLOTS: [(&str, &str, &str, &str); 5] = [
    (
        "linux-appimage",
        "linux-ubuntu-24_04-x86_64-production",
        "linux",
        "x86_64",
    ),
    (
        "linux-deb",
        "linux-ubuntu-24_04-x86_64-production",
        "linux",
        "x86_64",
    ),
    (
        "macos-app-development-adhoc",
        "macos-14-arm64-development-preview",
        "macos",
        "arm64",
    ),
    (
        "macos-dmg-development-adhoc",
        "macos-14-arm64-development-preview",
        "macos",
        "arm64",
    ),
    (
        "windows-installer-unsigned",
        "windows-11-24h2-x86_64-production",
        "windows",
        "x86_64",
    ),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFacts {
    pub app_version: String,
    pub release_sequence: u64,
    pub bundle_identity: String,
    pub artifacts: Vec<UnsignedArtifact>,
    pub bundled_runtime: BundledRuntime,
    pub macos_preview: MacosPreview,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedArtifact {
    pub artifact_slot_id: String,
    pub platform_scope_id: String,
    pub platform: String,
    pub architecture: String,
    pub artifact_sha256: HexDigest,
    pub byte_length: u64,
    pub minimum_os_policy: MinimumOsPolicy,
    pub profile_bindings: Vec<ProfileBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimumOsPolicy {
    pub policy_id: String,
    pub policy_sha256: HexDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBinding {
    pub profile_id: String,
    pub bundle_sha256: HexDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledRuntime {
    pub version: String,
    pub sha256: HexDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosPreview {
    pub platform_scope_id: String,
    pub artifact_slot_ids: Vec<String>,
    pub disposition: String,
    pub publication_allowed: bool,
}

pub(super) fn validate(value: &ReleaseFacts) -> Result<(), AuthorityError> {
    text(&value.app_version)?;
    id(&value.bundle_identity)?;
    if value.release_sequence == 0
        || value.artifacts.len() != SLOTS.len()
        || text(&value.bundled_runtime.version).is_err()
        || value.macos_preview.platform_scope_id != SLOTS[2].1
        || value.macos_preview.artifact_slot_ids != [SLOTS[2].0, SLOTS[3].0]
        || value.macos_preview.disposition != "development_preview"
        || value.macos_preview.publication_allowed
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    for (artifact, expected) in value.artifacts.iter().zip(SLOTS) {
        if (
            artifact.artifact_slot_id.as_str(),
            artifact.platform_scope_id.as_str(),
            artifact.platform.as_str(),
            artifact.architecture.as_str(),
        ) != expected
        {
            return Err(AuthorityError::NonCanonicalPayload);
        }
        id(&artifact.minimum_os_policy.policy_id)?;
        profiles(&artifact.profile_bindings)?;
    }
    Ok(())
}

fn profiles(value: &[ProfileBinding]) -> Result<(), AuthorityError> {
    if value.len() != 1 {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    for binding in value {
        id(&binding.profile_id)?;
    }
    let ordered = value.windows(2).all(|pair| {
        (pair[0].profile_id.as_str(), pair[0].bundle_sha256.0)
            < (pair[1].profile_id.as_str(), pair[1].bundle_sha256.0)
    });
    ordered
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}

fn text(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}

fn id(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}
