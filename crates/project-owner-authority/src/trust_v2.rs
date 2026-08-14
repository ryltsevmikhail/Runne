//! Version-2 successor trust configurations.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthorityError, SchemaDigest, trust_canonical::hex};

pub const CONFIG_SCHEMA_V2: &str = "gocode.project-owner.trust-config/2";
pub const POP_DOMAIN_V2: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/2";

/// Public successor trust configuration. V2 has no genesis form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerTrustConfigV2 {
    /// Fixed trust-config V2 schema identifier.
    pub schema_version: String,
    /// Repository governed by this trust configuration.
    pub repository_id: String,
    /// Fixed project-owner role.
    pub role: String,
    /// Strictly increasing key epoch.
    pub epoch: u64,
    /// Domain-separated identifier for `public_key`.
    pub key_id: [u8; 32],
    /// Ed25519 public-key bytes.
    pub public_key: [u8; 32],
    /// Exact monotonic schema pin set.
    pub schema_digests: Vec<SchemaDigest>,
    /// New-key proof of possession for the successor configuration.
    pub proof_of_possession: [u8; 64],
    /// SHA-256 of the canonical predecessor configuration.
    pub predecessor: [u8; 32],
    /// Schema version of the exact predecessor configuration.
    pub predecessor_schema_version: String,
}

/// Opaque V2 successor trust obtained only by anchored rotation verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrustConfigV2(ProjectOwnerTrustConfigV2);

impl VerifiedTrustConfigV2 {
    pub(crate) const fn config(&self) -> &ProjectOwnerTrustConfigV2 {
        &self.0
    }
}
impl std::ops::Deref for VerifiedTrustConfigV2 {
    type Target = ProjectOwnerTrustConfigV2;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only minting preserves opaque trust handle"
)]
pub(super) const fn verified_v2(config: ProjectOwnerTrustConfigV2) -> VerifiedTrustConfigV2 {
    VerifiedTrustConfigV2(config)
}

impl ProjectOwnerTrustConfigV2 {
    /// SHA-256 of the complete canonical V2 configuration.
    ///
    /// # Errors
    /// Returns an error when schema pins are not canonical.
    pub fn sha256(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(Sha256::digest(canonical_config_v2(self, true)?).into())
    }

    /// Parse only exact canonical V2 trust-configuration JSON.
    ///
    /// # Errors
    /// Returns a fail-closed error for malformed or noncanonical input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        crate::trust_v2_wire::parse(bytes)
    }

    /// Return exact canonical V2 JSON including one final LF.
    ///
    /// # Errors
    /// Returns an error when schema pins are not canonical.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_config_v2(self, true)
    }
}

/// Canonical V2 successor bytes, optionally omitting its proof of possession.
///
/// # Errors
/// Returns an error for empty, unsorted, duplicate, or malformed schema pins.
pub fn canonical_config_v2(
    config: &ProjectOwnerTrustConfigV2,
    include_pop: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if !valid_pins(&config.schema_digests) {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let pins = config.schema_digests.iter().map(pin_value).collect();
    let mut root = BTreeMap::from([
        ("epoch", Value::Number(config.epoch.into())),
        ("key_id", Value::String(hex(&config.key_id))),
        ("predecessor", Value::String(hex(&config.predecessor))),
        (
            "predecessor_schema_version",
            Value::String(config.predecessor_schema_version.clone()),
        ),
        (
            "public_key",
            Value::String(URL_SAFE_NO_PAD.encode(config.public_key)),
        ),
        ("repository_id", Value::String(config.repository_id.clone())),
        ("role", Value::String(config.role.clone())),
        ("schema_digests", Value::Array(pins)),
        (
            "schema_version",
            Value::String(config.schema_version.clone()),
        ),
    ]);
    if include_pop {
        root.insert(
            "proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(config.proof_of_possession)),
        );
    }
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Return the sole reviewed V2 target pin union.
#[must_use]
pub fn v2_trust_schema_digests() -> Vec<SchemaDigest> {
    let mut pins = crate::v2_platform_scope_schema_digests();
    pins.extend(crate::v3_reconciliation_schema_digests());
    pins.sort_by(|left, right| left.schema_id.as_bytes().cmp(right.schema_id.as_bytes()));
    pins
}

pub fn verify_v2_config(config: &ProjectOwnerTrustConfigV2) -> Result<(), AuthorityError> {
    if config.schema_version != CONFIG_SCHEMA_V2
        || config.repository_id != "gocode"
        || config.role != "PROJECT_OWNER"
        || config.epoch < 2
        || (config.epoch == 2
            && config.predecessor_schema_version != "gocode.project-owner.trust-config/1")
        || (config.epoch > 2 && config.predecessor_schema_version != CONFIG_SCHEMA_V2)
        || config.key_id != crate::key_id(&config.public_key)
        || config.schema_digests != v2_trust_schema_digests()
    {
        return Err(AuthorityError::InvalidGenesis);
    }
    let key = VerifyingKey::from_bytes(&config.public_key)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)?;
    key.verify_strict(
        &crate::framed_transcript(POP_DOMAIN_V2, &canonical_config_v2(config, false)?)?,
        &Signature::from_bytes(&config.proof_of_possession),
    )
    .map_err(|_| AuthorityError::InvalidProofOfPossession)
}

pub fn valid_pins(pins: &[SchemaDigest]) -> bool {
    !pins.is_empty()
        && pins
            .windows(2)
            .all(|pair| pair[0].schema_id.as_bytes() < pair[1].schema_id.as_bytes())
        && pins.iter().all(|pin| valid_schema_id(&pin.schema_id))
}

fn valid_schema_id(value: &str) -> bool {
    let Some((name, version)) = value
        .strip_prefix("gocode.")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    !name.is_empty()
        && !version.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn pin_value(pin: &SchemaDigest) -> Value {
    Value::Object(
        BTreeMap::from([
            ("schema_id".into(), Value::String(pin.schema_id.clone())),
            (
                "schema_sha256".into(),
                Value::String(hex(&pin.schema_sha256)),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
