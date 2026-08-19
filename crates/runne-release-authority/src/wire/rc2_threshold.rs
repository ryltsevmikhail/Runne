use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::common::{HexDigest, HexSignature, identifier, unique};
use crate::AuthorityError;

pub(super) const METADATA: &str = "runne.release.rc2-threshold-update-metadata-set/2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ThresholdMetadata {
    pub schema_version: String,
    pub root: SignedRoot,
    pub targets: SignedTargets,
    pub snapshot: SignedOnline,
    pub timestamp: SignedOnline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRoot {
    pub body: RootBody,
    pub successor_authorization: Vec<ThresholdSignature>,
    pub self_proof: Vec<ThresholdSignature>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedTargets {
    pub body: TargetsBody,
    pub root_authorization: Vec<ThresholdSignature>,
    pub self_proof: Vec<ThresholdSignature>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedOnline {
    pub body: OnlineBody,
    pub signature: ThresholdSignature,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootBody {
    pub role: String,
    pub candidate_sha256: HexDigest,
    pub inventory_sha256: HexDigest,
    pub version: u64,
    pub rollback_floor: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub frozen: bool,
    pub keyset: Vec<ThresholdKey>,
    pub predecessor_body_sha256: HexDigest,
    pub predecessor_keyset_sha256: HexDigest,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetsBody {
    pub role: String,
    pub candidate_sha256: HexDigest,
    pub inventory_sha256: HexDigest,
    pub version: u64,
    pub rollback_floor: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub frozen: bool,
    pub keyset: Vec<ThresholdKey>,
    pub root_body_sha256: HexDigest,
    pub root_body_length: u64,
    pub root_version: u64,
    pub targets: Vec<UpdateTarget>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OnlineBody {
    pub role: String,
    pub candidate_sha256: HexDigest,
    pub inventory_sha256: HexDigest,
    pub version: u64,
    pub rollback_floor: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub frozen: bool,
    pub key_id: String,
    pub predecessor_body_sha256: HexDigest,
    pub predecessor_body_length: u64,
    pub predecessor_version: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ThresholdKey {
    pub key_id: String,
    pub public_key: HexDigest,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateTarget {
    pub slot: String,
    pub app_version: String,
    pub release_sequence: u64,
    pub bundle_id: String,
    pub platform: String,
    pub architecture: String,
    pub artifact_sha256: HexDigest,
    pub artifact_length: u64,
    pub min_os_policy_id: String,
    pub min_os_policy_sha256: HexDigest,
    pub profiles: Vec<UpdateProfile>,
    pub runtime_version: String,
    pub runtime_sha256: HexDigest,
    pub channel_selector: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateProfile {
    pub profile_id: String,
    pub bundle_sha256: HexDigest,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ThresholdSignature {
    pub key_id: String,
    pub signature: HexSignature,
}

pub(super) fn metadata(value: &ThresholdMetadata) -> Result<(), AuthorityError> {
    if value.schema_version != METADATA
        || !root(&value.root.body)
        || !targets(&value.targets.body)
        || !online(&value.snapshot.body, "snapshot")
        || !online(&value.timestamp.body, "timestamp")
        || value.snapshot.body.key_id == value.timestamp.body.key_id
        || !value
            .targets
            .body
            .targets
            .iter()
            .all(|target| target.channel_selector == value.targets.body.targets[0].channel_selector)
        || value.root.body.candidate_sha256 != value.targets.body.candidate_sha256
        || value.root.body.inventory_sha256 != value.targets.body.inventory_sha256
        || value.root.body.candidate_sha256 != value.snapshot.body.candidate_sha256
        || value.root.body.inventory_sha256 != value.snapshot.body.inventory_sha256
        || value.root.body.candidate_sha256 != value.timestamp.body.candidate_sha256
        || value.root.body.inventory_sha256 != value.timestamp.body.inventory_sha256
        || !links(value)
        || !proofs(&value.root.successor_authorization)
        || !proofs(&value.root.self_proof)
        || !proofs(&value.targets.root_authorization)
        || !proofs(&value.targets.self_proof)
        || !signature(&value.snapshot.signature)
        || !signature(&value.timestamp.signature)
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}

fn links(value: &ThresholdMetadata) -> bool {
    let Ok(root) = canonical_body(&value.root.body) else {
        return false;
    };
    let Ok(targets) = canonical_body(&value.targets.body) else {
        return false;
    };
    let Ok(snapshot) = canonical_body(&value.snapshot.body) else {
        return false;
    };
    value.targets.body.root_body_sha256.0 == crate::Digest::from_bytes(Sha256::digest(&root).into())
        && value.targets.body.root_body_length == root.len() as u64
        && value.targets.body.root_version == value.root.body.version
        && value.snapshot.body.predecessor_body_sha256.0
            == crate::Digest::from_bytes(Sha256::digest(&targets).into())
        && value.snapshot.body.predecessor_body_length == targets.len() as u64
        && value.snapshot.body.predecessor_version == value.targets.body.version
        && value.timestamp.body.predecessor_body_sha256.0
            == crate::Digest::from_bytes(Sha256::digest(&snapshot).into())
        && value.timestamp.body.predecessor_body_length == snapshot.len() as u64
        && value.timestamp.body.predecessor_version == value.snapshot.body.version
        && value.targets.body.rollback_floor == value.root.body.rollback_floor
        && value.targets.body.expires_at == value.root.body.expires_at
        && value.targets.body.revocation_epoch == value.root.body.revocation_epoch
        && value.snapshot.body.rollback_floor == value.root.body.rollback_floor
        && value.snapshot.body.expires_at == value.root.body.expires_at
        && value.snapshot.body.revocation_epoch == value.root.body.revocation_epoch
        && value.timestamp.body.rollback_floor == value.root.body.rollback_floor
        && value.timestamp.body.expires_at == value.root.body.expires_at
        && value.timestamp.body.revocation_epoch == value.root.body.revocation_epoch
}

fn root(value: &RootBody) -> bool {
    value.role == "root"
        && common(
            value.version,
            value.rollback_floor,
            value.expires_at,
            value.revocation_epoch,
            value.frozen,
        )
        && keyset(&value.keyset)
}
fn targets(value: &TargetsBody) -> bool {
    value.role == "targets"
        && common(
            value.version,
            value.rollback_floor,
            value.expires_at,
            value.revocation_epoch,
            value.frozen,
        )
        && keyset(&value.keyset)
        && value.root_version > 0
        && value.targets.len() == 3
        && value.targets.iter().map(|x| x.slot.as_str()).eq([
            "linux-appimage",
            "linux-deb",
            "windows-installer-unsigned",
        ])
        && value.targets.iter().all(target)
}
fn online(value: &OnlineBody, role: &str) -> bool {
    value.role == role
        && common(
            value.version,
            value.rollback_floor,
            value.expires_at,
            value.revocation_epoch,
            value.frozen,
        )
        && value.predecessor_version > 0
        && identifier(&value.key_id).is_ok()
}
const fn common(version: u64, floor: u64, expires: u64, epoch: u64, frozen: bool) -> bool {
    version > 0 && floor > 0 && expires > 0 && epoch > 0 && !frozen
}
fn keyset(value: &[ThresholdKey]) -> bool {
    value.len() == 3
        && unique(&value.iter().map(|x| x.key_id.clone()).collect::<Vec<_>>())
        && value.iter().all(|x| identifier(&x.key_id).is_ok())
}
fn target(value: &UpdateTarget) -> bool {
    identifier(&value.slot).is_ok()
        && !value.app_version.is_empty()
        && value.release_sequence > 0
        && identifier(&value.bundle_id).is_ok()
        && matches!(value.platform.as_str(), "linux" | "windows")
        && matches!(value.architecture.as_str(), "x86_64" | "aarch64")
        && value.artifact_length > 0
        && identifier(&value.min_os_policy_id).is_ok()
        && !value.profiles.is_empty()
        && value
            .profiles
            .iter()
            .all(|profile| identifier(&profile.profile_id).is_ok())
        && !value.runtime_version.is_empty()
        && identifier(&value.channel_selector).is_ok()
}
fn proofs(value: &[ThresholdSignature]) -> bool {
    value.len() == 2
        && unique(&value.iter().map(|x| x.key_id.clone()).collect::<Vec<_>>())
        && value.iter().all(signature)
}
fn signature(value: &ThresholdSignature) -> bool {
    identifier(&value.key_id).is_ok()
}

pub(super) fn canonical_body<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthorityError> {
    serde_json::to_vec(&super::sorted_value(
        serde_json::to_value(value).map_err(|_| AuthorityError::NonCanonicalPayload)?,
    ))
    .map_err(|_| AuthorityError::NonCanonicalPayload)
}
