//! Root-signed publication destination allowlist model and opaque verification handle.

use serde::Deserialize;

/// Fixed root-controlled destination allowlist schema.
pub const DESTINATION_ALLOWLIST_SCHEMA_V1: &str =
    "gocode.project-owner.publication-destination-allowlist/1";

/// One permitted destination and channel pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicationDestinationV1 {
    pub destination: String,
    pub channel: String,
    pub permitted_effect_kinds: Vec<String>,
    pub executor_policy_sha256: [u8; 32],
}

/// Raw root-signed destination allowlist fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicationDestinationAllowlistV1 {
    pub schema_version: String,
    pub repository_id: String,
    pub generation: u64,
    pub policy_id: String,
    pub destinations: Vec<PublicationDestinationV1>,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub revocation_epoch: u64,
    pub key_id: String,
    pub key_epoch: u64,
    /// Detached Ed25519 signature in unpadded base64url wire representation.
    #[serde(default)]
    pub signature: String,
}

/// Move-only verified root-controlled destination authority.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedDestinationAllowlist {
    digest: [u8; 32],
    generation: u64,
    destinations: Vec<PublicationDestinationV1>,
    issued_at: String,
    not_before: String,
    expires_at: String,
    revocation_epoch: u64,
    key_id: String,
    key_epoch: u64,
    policy_id: String,
}
/// Cryptographically complete, non-authorizing destination allowlist `/1` result.
///
/// ```compile_fail
/// fn authorize(value: runne_project_owner_authority::PrevalidatedDestinationAllowlistV1) {
///     let _ = value.destinations();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedDestinationAllowlistV1 {
    pub(crate) digest: [u8; 32],
    pub(crate) unsigned_sha256: [u8; 32],
    pub(crate) value: PublicationDestinationAllowlistV1,
    pub(crate) scope: crate::DestinationAllowlistAdmissionScope,
}
/// Root-signature-verified allowlist instance before receipt `/5` binding or admission.
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedRootSignedDestinationAllowlistV1 {
    pub(crate) digest: [u8; 32],
    pub(crate) unsigned_sha256: [u8; 32],
    pub(crate) value: PublicationDestinationAllowlistV1,
    pub(crate) root_public_key: [u8; 32],
}
impl VerifiedDestinationAllowlist {
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub fn destinations(&self) -> &[PublicationDestinationV1] {
        &self.destinations
    }
    #[must_use]
    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }
    #[must_use]
    pub fn not_before(&self) -> &str {
        &self.not_before
    }
    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

/// Crate-only mint: a verified allowlist is produced exclusively by raw verification.
#[expect(
    clippy::too_many_arguments,
    reason = "every admission fact is retained by the move-only handle"
)]
pub const fn verified_destination_allowlist(
    digest: [u8; 32],
    generation: u64,
    destinations: Vec<PublicationDestinationV1>,
    issued_at: String,
    not_before: String,
    expires_at: String,
    revocation_epoch: u64,
    key_id: String,
    key_epoch: u64,
    policy_id: String,
) -> VerifiedDestinationAllowlist {
    VerifiedDestinationAllowlist {
        digest,
        generation,
        destinations,
        issued_at,
        not_before,
        expires_at,
        revocation_epoch,
        key_id,
        key_epoch,
        policy_id,
    }
}
