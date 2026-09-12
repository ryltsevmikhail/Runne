use serde::{Deserialize, Serialize};

use crate::{QualificationRunBootstrapError, MAX_RUN_BOOTSTRAP_PROOF_BYTES};

pub const SCHEMA_VERSION: &str = "runne/macos-xpc-dpk-run-bootstrap/v1";
pub const SIGNATURE_DOMAIN: &[u8] = b"runne/macos-xpc-dpk-run-bootstrap/v1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBootstrapWire {
    pub schema_version: String,
    pub context_id: String,
    pub challenge: String,
    pub candidate_sha256: String,
    pub raw_v3_tuple_sha256: String,
    pub source_revision: String,
    pub workflow_run_id: String,
    pub namespace_sha256: String,
    pub manifest_sha256: String,
    pub profile_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub run_not_after: u64,
    pub nonce: String,
    pub signature: SignatureWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureWire {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Deserialize, Serialize)]
struct UnsignedWire<'a> {
    schema_version: &'a str,
    context_id: &'a str,
    challenge: &'a str,
    candidate_sha256: &'a str,
    raw_v3_tuple_sha256: &'a str,
    source_revision: &'a str,
    workflow_run_id: &'a str,
    namespace_sha256: &'a str,
    manifest_sha256: &'a str,
    profile_sha256: &'a str,
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    nonce: &'a str,
}

pub fn decode(bytes: &[u8]) -> Result<RunBootstrapWire, QualificationRunBootstrapError> {
    if bytes.is_empty() || bytes.len() > MAX_RUN_BOOTSTRAP_PROOF_BYTES {
        return Err(QualificationRunBootstrapError::InvalidProof);
    }
    let proof: RunBootstrapWire =
        serde_json::from_slice(bytes).map_err(|_| QualificationRunBootstrapError::InvalidProof)?;
    (serde_json::to_vec(&proof).ok().as_deref() == Some(bytes))
        .then_some(proof)
        .ok_or(QualificationRunBootstrapError::InvalidProof)
}

pub fn signing_payload(
    proof: &RunBootstrapWire,
) -> Result<Vec<u8>, QualificationRunBootstrapError> {
    let unsigned = UnsignedWire {
        schema_version: &proof.schema_version,
        context_id: &proof.context_id,
        challenge: &proof.challenge,
        candidate_sha256: &proof.candidate_sha256,
        raw_v3_tuple_sha256: &proof.raw_v3_tuple_sha256,
        source_revision: &proof.source_revision,
        workflow_run_id: &proof.workflow_run_id,
        namespace_sha256: &proof.namespace_sha256,
        manifest_sha256: &proof.manifest_sha256,
        profile_sha256: &proof.profile_sha256,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        run_not_after: proof.run_not_after,
        nonce: &proof.nonce,
    };
    let canonical =
        serde_json::to_vec(&unsigned).map_err(|_| QualificationRunBootstrapError::InvalidProof)?;
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
#[derive(Deserialize, Serialize)]
struct TestUnsignedWire {
    schema_version: String,
    context_id: String,
    challenge: String,
    candidate_sha256: String,
    raw_v3_tuple_sha256: String,
    source_revision: String,
    workflow_run_id: String,
    namespace_sha256: String,
    manifest_sha256: String,
    profile_sha256: String,
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    nonce: String,
}

#[cfg(test)]
pub fn test_signing_payload(
    value: &serde_json::Value,
) -> Result<Vec<u8>, QualificationRunBootstrapError> {
    let unsigned: TestUnsignedWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationRunBootstrapError::InvalidProof)?;
    let canonical =
        serde_json::to_vec(&unsigned).map_err(|_| QualificationRunBootstrapError::InvalidProof)?;
    let mut payload = SIGNATURE_DOMAIN.to_vec();
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
pub fn test_canonical(
    value: &serde_json::Value,
) -> Result<Vec<u8>, QualificationRunBootstrapError> {
    let proof: RunBootstrapWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationRunBootstrapError::InvalidProof)?;
    serde_json::to_vec(&proof).map_err(|_| QualificationRunBootstrapError::InvalidProof)
}
