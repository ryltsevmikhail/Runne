//! Version-3 successor trust configuration, reserved for promotion contracts.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthorityError, SchemaDigest, trust_canonical::hex};

pub const CONFIG_SCHEMA_V3: &str = "gocode.project-owner.trust-config/3";
pub const POP_DOMAIN_V3: &[u8] = b"gocode.project-owner.rotation-new-proof-of-possession/3";

/// Public V3 successor trust configuration. V3 has no genesis form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerTrustConfigV3 {
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

/// Opaque V3 promotion trust obtained only through a verified V2-to-V3 rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTrustConfigV3(ProjectOwnerTrustConfigV3);

impl VerifiedTrustConfigV3 {
    pub(crate) const fn config(&self) -> &ProjectOwnerTrustConfigV3 {
        &self.0
    }
}
impl std::ops::Deref for VerifiedTrustConfigV3 {
    type Target = ProjectOwnerTrustConfigV3;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only minting preserves opaque trust handle"
)]
pub(super) const fn verified_v3(config: ProjectOwnerTrustConfigV3) -> VerifiedTrustConfigV3 {
    VerifiedTrustConfigV3(config)
}

impl ProjectOwnerTrustConfigV3 {
    /// Return the SHA-256 of canonical V3 configuration bytes.
    ///
    /// # Errors
    /// Returns an error for noncanonical schema pins.
    pub fn sha256(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(Sha256::digest(canonical_config_v3(self, true)?).into())
    }

    /// Parse only exact canonical V3 trust-configuration JSON.
    ///
    /// # Errors
    /// Returns an error for malformed or noncanonical bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityError> {
        crate::trust_v3_wire::parse(bytes)
    }

    /// Return exact canonical V3 JSON including one final LF.
    ///
    /// # Errors
    /// Returns an error for noncanonical schema pins.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, AuthorityError> {
        canonical_config_v3(self, true)
    }
}

/// Canonical V3 successor bytes, optionally omitting proof of possession.
///
/// # Errors
/// Returns an error for empty, unsorted, duplicate, or malformed schema pins.
pub fn canonical_config_v3(
    config: &ProjectOwnerTrustConfigV3,
    include_pop: bool,
) -> Result<Vec<u8>, AuthorityError> {
    if !crate::trust_v2::valid_pins(&config.schema_digests) {
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

/// Return the exact finalized V3 promotion schema pin union.
///
/// # Errors
/// Returns the canonical complete pin set used for V3 trust verification.
pub fn v3_trust_schema_digests() -> Result<Vec<SchemaDigest>, AuthorityError> {
    let values = [
        (
            "gocode.governance.v1-platform-scope-decision/1",
            "dba89e59dfa2b9a232203353d45b56e24497353b701d318e9569fc3cb791602f",
        ),
        (
            "gocode.project-owner.authority-receipt/2",
            "f9c21f4485b66bec34c8fd07402cd3b7331bf55b874d52833ff47ee038d482ea",
        ),
        (
            "gocode.project-owner.authority-receipt/3",
            "d1a5666b21be5e09d34ef6bf30ee16806e39cf564856161d5404de4874447a2b",
        ),
        (
            "gocode.project-owner.authority-receipt/4",
            "51aa11f64eeaaba71098cf99cf57047859a38e4afc02db5ab3bc8d4e56e0d204",
        ),
        (
            "gocode.rc0.post-rc0-platform-composed-universe/1",
            "c64164ee430e316affd9781a47a450f147f406cb09f2bdf31e14f333045dd8de",
        ),
        (
            "gocode.release.post-rc0-stage-envelope/1",
            "e7c020c0c8b2d28680f80bf2bce0616e88c9baa31d161bc0551c09055e81af98",
        ),
        (
            "gocode.release.promotion-state-snapshot/1",
            "c19b74cec8581ae0b2a4440eaaed1a89a58f9831856a1819d65b2c604e773a7f",
        ),
        (
            "gocode.release.publication-manifest/1",
            "c2214bbc991de8be22a29cc87804ec9eca471de44b1c80f4fd67c3b17b85d2a2",
        ),
        (
            "gocode.release.rc1-qualification-decision/1",
            "c3969fbc0a7c382e475401e00de8cf43538b1ca1f9d8e6efca35ef22590049ef",
        ),
        (
            "gocode.release.rc2-signed-artifact-record/1",
            "bfa6908bf65be56d733faad09168bdf7e6033bacc924695b48d6655dc39a112b",
        ),
        (
            "gocode.release.rc2-signing-authorization/1",
            "49904458730d7a4971d92332747fedf9a45f5fb3a60854888e83dd9d330dc64e",
        ),
        (
            "gocode.release.rc2-threshold-update-metadata-set/1",
            "ca5137f3fcc1401e75cefdca11ca9f32ac9f2863e5ef6bcce26deda3a3f21c59",
        ),
        (
            "gocode.release.rc3-publication-authorization/1",
            "fd5c4749ee05f9942510cdee544e92fc40189eb49edd15609f8ff53535dc107e",
        ),
        (
            "gocode.release.signed-envelope-inventory/1",
            "5301f07f5ac32b2e25bf420da6fc85c76926bc7e22c35457135ee38393af66fe",
        ),
        (
            "gocode.release.signed-envelope-verification-report/1",
            "49c33b4f046db4f298a44de5fb1c345fda133aa8d27a426568141b87698385d4",
        ),
        (
            "gocode.release.unsigned-candidate-manifest/1",
            "6dc7544e56cf793b231e238406139fcbfb8f1e724f70336fb8645f3e7f515067",
        ),
        (
            "gocode.v1-platform-scope-claim-migration/1",
            "bc6cdc1861fe39e4be0ec118672a333a7d6994649d15f43b13611f8d35dd8285",
        ),
    ];
    Ok(values
        .into_iter()
        .map(|(schema_id, source)| SchemaDigest {
            schema_id: schema_id.into(),
            schema_sha256: decode_pin(source),
        })
        .collect())
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

/// Verify a final V3 configuration.
///
/// # Errors
/// Returns an error for a non-final, malformed, or unsigned successor.
pub fn verify_v3_config(config: &ProjectOwnerTrustConfigV3) -> Result<(), AuthorityError> {
    if config.schema_version != CONFIG_SCHEMA_V3
        || config.repository_id != "gocode"
        || config.role != "PROJECT_OWNER"
        || config.epoch < 3
        || config.predecessor_schema_version != "gocode.project-owner.trust-config/2"
        || config.key_id != crate::key_id(&config.public_key)
        || config.schema_digests != v3_trust_schema_digests()?
    {
        return Err(AuthorityError::InvalidGenesis);
    }
    let key = VerifyingKey::from_bytes(&config.public_key)
        .map_err(|_| AuthorityError::InvalidProofOfPossession)?;
    key.verify_strict(
        &crate::framed_transcript(POP_DOMAIN_V3, &canonical_config_v3(config, false)?)?,
        &Signature::from_bytes(&config.proof_of_possession),
    )
    .map_err(|_| AuthorityError::InvalidProofOfPossession)
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
