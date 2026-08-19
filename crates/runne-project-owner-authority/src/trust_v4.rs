//! Version-4 successor trust configuration for the active V5 authority chain.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthorityError, SchemaDigest, trust_canonical::hex};

pub const CONFIG_SCHEMA_V4: &str = "runne.project-owner.trust-config/4";
pub const POP_DOMAIN_V4: &[u8] = b"runne.project-owner.rotation-new-proof-of-possession/4";

/// Public V4 successor configuration. Only a verified V3-to-V4 rotation may mint it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerTrustConfigV4 {
    pub schema_version: String,
    pub repository_id: String,
    pub role: String,
    pub epoch: u64,
    pub key_id: [u8; 32],
    pub public_key: [u8; 32],
    pub schema_digests: Vec<SchemaDigest>,
    pub proof_of_possession: [u8; 64],
    pub predecessor: [u8; 32],
    pub predecessor_schema_version: String,
}

/// Opaque active-chain root trust; it cannot be constructed outside this crate.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedTrustConfigV4(ProjectOwnerTrustConfigV4);
impl VerifiedTrustConfigV4 {
    pub(crate) const fn config(&self) -> &ProjectOwnerTrustConfigV4 {
        &self.0
    }
}
impl std::ops::Deref for VerifiedTrustConfigV4 {
    type Target = ProjectOwnerTrustConfigV4;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[expect(
    clippy::redundant_pub_crate,
    reason = "opaque trust requires crate-only minting"
)]
pub(super) const fn verified_v4(value: ProjectOwnerTrustConfigV4) -> VerifiedTrustConfigV4 {
    VerifiedTrustConfigV4(value)
}

impl ProjectOwnerTrustConfigV4 {
    /// Return the SHA-256 of canonical V4 configuration bytes.
    ///
    /// # Errors
    /// Returns an error when canonical schema pins are malformed.
    pub fn sha256(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(Sha256::digest(canonical_config_v4(self, true)?).into())
    }
    /// Return exact canonical JSON including a final LF.
    ///
    /// # Errors
    /// Returns an error when canonical schema pins are malformed.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_config_v4(self, true)
    }
}

/// Canonical V4 trust bytes, optionally omitting proof of possession.
///
/// # Errors
/// Returns an error when schema pins are not canonical.
pub fn canonical_config_v4(
    value: &ProjectOwnerTrustConfigV4,
    include_pop: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if !crate::trust_v2::valid_pins(&value.schema_digests) {
        return Err(AuthorityError::InvalidSchemaDigests);
    }
    let mut root = BTreeMap::from([
        ("epoch", Value::Number(value.epoch.into())),
        ("key_id", Value::String(hex(&value.key_id))),
        ("predecessor", Value::String(hex(&value.predecessor))),
        (
            "predecessor_schema_version",
            Value::String(value.predecessor_schema_version.clone()),
        ),
        (
            "public_key",
            Value::String(URL_SAFE_NO_PAD.encode(value.public_key)),
        ),
        ("repository_id", Value::String(value.repository_id.clone())),
        ("role", Value::String(value.role.clone())),
        (
            "schema_digests",
            Value::Array(value.schema_digests.iter().map(pin).collect()),
        ),
        (
            "schema_version",
            Value::String(value.schema_version.clone()),
        ),
    ]);
    if include_pop {
        root.insert(
            "proof_of_possession",
            Value::String(URL_SAFE_NO_PAD.encode(value.proof_of_possession)),
        );
    }
    let mut bytes = serde_json::to_vec(&root).map_err(|_| AuthorityError::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Return V4 pin union only after every successor leaf schema has immutable bytes.
///
/// # Errors
/// Always returns the explicit fail-closed pending-pins error until leaf schemas stabilize.
#[allow(clippy::missing_const_for_fn)]
pub fn v4_trust_schema_digests() -> Result<Vec<SchemaDigest>, AuthorityError> {
    #[cfg(test)]
    {
        Ok(v4_leaf_schema_digests())
    }
    #[cfg(not(test))]
    Err(AuthorityError::TrustV4PinsNotFinalized)
}

/// Exact successor leaf pin union for the V5 authority chain (sorted, unique).
///
/// Digests are the SHA-256 of the corresponding checked-in `docs/schemas/*.schema.json`
/// files and are re-verified in `receipt_v5_wire_tests`. Production builds never call this.
#[cfg(test)]
fn v4_leaf_schema_digests() -> Vec<SchemaDigest> {
    [
        (
            "runne.project-owner.authority-receipt/5",
            "efc3baa15c4a813325143ebf19a3b8cbbd01c9809ccf0be526c1223f2dd1b297",
        ),
        (
            "runne.project-owner.key-rotation/4",
            "4b72392566f7dd6686ee1f72f7c8a9f117098eba819dc5ee86988aac08005c62",
        ),
        (
            "runne.project-owner.publication-destination-allowlist/1",
            "ce1ac4c808c57d37e91a332c39517769da83737d016efd1a7283574c6e5c3acd",
        ),
        (
            "runne.project-owner.trust-config/4",
            "f55edfbd8d3ab7f49428bd718f3c37fab332c669fd48886680eefb1a97b3607e",
        ),
        (
            "runne.release.post-rc0-evidence-envelope/2",
            "20925f03930119f600a7f1c2cb1a8bd969839be0b7dc33247145ad1cf100d18d",
        ),
        (
            "runne.release.post-rc0-stage-envelope/2",
            "7b64f67e461a83fa33de5310ae8009cc3e009a1ee7358947ddd86a85fafc32d5",
        ),
        (
            "runne.release.rc1-qualification-decision/1",
            "4b906fed479c58571a305b862f17c36d558c3fa5ac9f37f56972504653d56e00",
        ),
        (
            "runne.release.rc2-native-evidence/1",
            "b049f39d5ec8fe1cdf0b03231445ab7cd0401abfa2c94d120f023f33c8a224df",
        ),
        (
            "runne.release.rc2-signing-authorization/1",
            "8cae65952f9cccce55ee3c5326cdc6875954e0bda45015a1ab8cecce6687d37a",
        ),
        (
            "runne.release.rc2-signing-review/1",
            "76208f4b4724c4d605d57c63badd7fda7b68125cf756167fdad20ddc51606d0e",
        ),
        (
            "runne.release.rc2-update-metadata-issuance/1",
            "b1841a24166ac6f7a84cb19f25159a30fffbf1c5ae14c81afc6e83b92085adc8",
        ),
        (
            "runne.release.rc3-final-review/1",
            "4f5fd7b0109fb6d2fc8b01125e13aa112792a5e4a5309afdf428f2738a5bb2fd",
        ),
        (
            "runne.release.rc3-publication-authorization/2",
            "b9b4a1fdf346d83c3bb31743a3af15f2173436a852cd592151e5844b960b260c",
        ),
    ]
    .into_iter()
    .map(|(schema_id, source)| SchemaDigest {
        schema_id: schema_id.into(),
        schema_sha256: decode_pin(source),
    })
    .collect()
}

#[cfg(test)]
fn decode_pin(source: &str) -> [u8; 32] {
    let mut value = [0; 32];
    for (index, pair) in source.as_bytes().chunks_exact(2).enumerate() {
        value[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    value
}

#[cfg(test)]
const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

/// Verify a finalized V4 configuration.
///
/// # Errors
/// Returns an error for a non-final, malformed, or unsigned successor.
pub fn verify_v4_config(value: &ProjectOwnerTrustConfigV4) -> Result<(), AuthorityError> {
    if value.schema_version != CONFIG_SCHEMA_V4
        || value.repository_id != "runne"
        || value.role != "PROJECT_OWNER"
        || value.epoch < 4
        || value.predecessor_schema_version != "runne.project-owner.trust-config/3"
        || value.key_id != crate::key_id(&value.public_key)
        || value.schema_digests != v4_trust_schema_digests()?
    {
        return Err(AuthorityError::InvalidGenesis);
    }
    VerifyingKey::from_bytes(&value.public_key)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)?
        .verify_strict(
            &crate::framed_transcript(POP_DOMAIN_V4, &canonical_config_v4(value, false)?)?,
            &Signature::from_bytes(&value.proof_of_possession),
        )
        .map_err(|_| AuthorityError::InvalidProofOfPossession)
}

fn pin(value: &SchemaDigest) -> Value {
    Value::Object(
        BTreeMap::from([
            ("schema_id".into(), Value::String(value.schema_id.clone())),
            (
                "schema_sha256".into(),
                Value::String(hex(&value.schema_sha256)),
            ),
        ])
        .into_iter()
        .collect(),
    )
}
