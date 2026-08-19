//! Version-3 successor trust configuration, reserved for promotion contracts.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthorityError, SchemaDigest, trust_canonical::hex};

pub const CONFIG_SCHEMA_V3: &str = "runne.project-owner.trust-config/3";
pub const POP_DOMAIN_V3: &[u8] = b"runne.project-owner.rotation-new-proof-of-possession/3";

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
            "runne.governance.v1-platform-scope-decision/1",
            "20351f7dab0c80e0d45dda943b13908d81ad910ff4a67cf9231d02ed67ed1f1a",
        ),
        (
            "runne.project-owner.authority-receipt/2",
            "775c73acab7c7964ada3ea4710af4c2823f77b488470d76617bfb633f5a52598",
        ),
        (
            "runne.project-owner.authority-receipt/3",
            "4938640a3f2c7e66f7425988b3c4d30bd89f57514aea518576cd2c603b8d232b",
        ),
        (
            "runne.project-owner.authority-receipt/4",
            "c4bd275f49e9c7e1a80106e5b265c1f6c28d203c752658b545a1c1cea8305b84",
        ),
        (
            "runne.rc0.post-rc0-platform-composed-universe/1",
            "cfcb48c0816cc88064e64b81bf6e9b27bb7de778dfa9ceeb59446883422bfb3b",
        ),
        (
            "runne.release.post-rc0-stage-envelope/1",
            "acb212ac09f60b46fb6c0627a2d129767baa222122a4143b651e73f3bfb0b583",
        ),
        (
            "runne.release.promotion-state-snapshot/1",
            "59c974ce1744421170839bbd5cee04b894041c8110677cdcc57724a6b5ed3c1d",
        ),
        (
            "runne.release.publication-manifest/1",
            "def0c61c4150339ad0b2b98739134b8e03f10b0ec37c64a436137354f5d79e7a",
        ),
        (
            "runne.release.rc1-qualification-decision/1",
            "4b906fed479c58571a305b862f17c36d558c3fa5ac9f37f56972504653d56e00",
        ),
        (
            "runne.release.rc2-signed-artifact-record/1",
            "1281d9876e3147742c355dad951ba92e70e0232b63f83dc76e3cb9ec941a2526",
        ),
        (
            "runne.release.rc2-signing-authorization/1",
            "8cae65952f9cccce55ee3c5326cdc6875954e0bda45015a1ab8cecce6687d37a",
        ),
        (
            "runne.release.rc2-threshold-update-metadata-set/1",
            "817352c6dc596ef088669a55ae6bde1298c43acf8c94388c8cbd3a0b7bb71cf8",
        ),
        (
            "runne.release.rc3-publication-authorization/1",
            "7973977602b15bb15a4e3dd5c244a76423fb20bd2cecc774514e8f353b1df863",
        ),
        (
            "runne.release.signed-envelope-inventory/1",
            "306ef13a6746acc2d48b3907ba1935d28c179598a475f80d6178442b7f5e4609",
        ),
        (
            "runne.release.signed-envelope-verification-report/1",
            "83087371e6cd8ca5be0ae880159f61ab02987677a39867b39dc5c14ba5fae879",
        ),
        (
            "runne.release.unsigned-candidate-manifest/1",
            "121b5cb8a860ef1053d2da8f0bfba6e94a09c117fa663ed720da6a10c60e1d37",
        ),
        (
            "runne.v1-platform-scope-claim-migration/1",
            "9384adf3bc7ba368cad052573d0483c013d98fba5c2452fb521aa911093ddbdb",
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
        || config.repository_id != "runne"
        || config.role != "PROJECT_OWNER"
        || config.epoch < 3
        || config.predecessor_schema_version != "runne.project-owner.trust-config/2"
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
