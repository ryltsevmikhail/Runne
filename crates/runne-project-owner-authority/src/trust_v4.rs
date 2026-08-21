//! Version-4 successor trust configuration for the active V5 authority chain.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthorityError, SchemaDigest, trust_canonical::hex};

pub const CONFIG_SCHEMA_V4: &str = "gocode.project-owner.trust-config/4";
pub const POP_DOMAIN_V4: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/4";

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

/// Return the finalized immutable V4 pin union for every successor leaf schema.
///
/// # Errors
/// This function currently returns the finalized immutable pin set.
pub fn v4_trust_schema_digests() -> Result<Vec<SchemaDigest>, AuthorityError> {
    Ok(v4_leaf_schema_digests())
}

/// Exact successor leaf pin union for the V5 authority chain (sorted, unique).
///
/// Digests are the SHA-256 of the corresponding checked-in `docs/schemas/*.schema.json`
/// files and are re-verified in `receipt_v5_wire_tests`.
fn v4_leaf_schema_digests() -> Vec<SchemaDigest> {
    [
        (
            "gocode.project-owner.authority-receipt/5",
            "5fa1de7c921acc5fe64f650e92e220b24390992e612c4c46ec0e364e2bec6340",
        ),
        (
            "gocode.project-owner.key-rotation/4",
            "f5fa4fc7021e215a6b937caf924500b60d43bc19a47e9737de91001ed81d5d04",
        ),
        (
            "gocode.project-owner.publication-destination-allowlist/1",
            "4143248c3da7032e8052afcde3d9ad1fb02303c03bfd98e1f90848829461ecbd",
        ),
        (
            "gocode.project-owner.trust-config/4",
            "187f0ed29342b263eaef98f961147f0a32d0e4b61da270604152980ac5c7fa87",
        ),
        (
            "gocode.release.post-rc0-evidence-envelope/2",
            "ed550775038dd782dd1e9581611223b4a2a0531fe2fefa582360d5e96ce2fbb3",
        ),
        (
            "gocode.release.post-rc0-stage-envelope/2",
            "003b932d8c44ef077e2e4ce9dc3e1d32d408e64eb8cf3c80d17669a7022f0538",
        ),
        (
            "gocode.release.rc1-qualification-decision/1",
            "c3969fbc0a7c382e475401e00de8cf43538b1ca1f9d8e6efca35ef22590049ef",
        ),
        (
            "gocode.release.rc2-native-evidence/1",
            "cb0ccf3b635200aa43614c362f631aca3d0feba91fa496512bb908d157ed3ae9",
        ),
        (
            "gocode.release.rc2-signing-authorization/1",
            "49904458730d7a4971d92332747fedf9a45f5fb3a60854888e83dd9d330dc64e",
        ),
        (
            "gocode.release.rc2-signing-review/1",
            "49aa1c4b02a078096ef535fc32ecbfe13457141d5d2b0f0af594d3948f80b1a3",
        ),
        (
            "gocode.release.rc2-update-metadata-issuance/1",
            "64a299a83c1d31a994b34b1aa97cfb3c7f74929a7d947d7366b52c7cc297bc58",
        ),
        (
            "gocode.release.rc3-final-review/1",
            "0c5376d127b18073f2527678aa508e64b35c4a6ab084b9d5eba885857f167d42",
        ),
        (
            "gocode.release.rc3-publication-authorization/2",
            "d634758735b0c8c9a31d9fa8d9b960b49235e6059965cc3984dd18bb49b7f8ef",
        ),
    ]
    .into_iter()
    .map(|(schema_id, source)| SchemaDigest {
        schema_id: schema_id.into(),
        schema_sha256: decode_pin(source),
    })
    .collect()
}

fn decode_pin(source: &str) -> [u8; 32] {
    let mut value = [0; 32];
    for (index, pair) in source.as_bytes().chunks_exact(2).enumerate() {
        value[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    value
}

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
        || value.repository_id != "gocode"
        || value.role != "PROJECT_OWNER"
        || value.epoch < 4
        || value.predecessor_schema_version != "gocode.project-owner.trust-config/3"
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
