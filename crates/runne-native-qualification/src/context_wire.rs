use serde::{Deserialize, Serialize};

use crate::{MAX_RUN_CONTEXT_BYTES, QualificationRunContextError};

pub const SCHEMA_VERSION: &str = "runne/macos-xpc-dpk-run-context/v1";
pub const SIGNATURE_DOMAIN: &[u8] = b"runne/macos-xpc-dpk-run-context/v1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunContextWire {
    pub schema_version: String,
    pub context_id: String,
    pub scenario_id: String,
    pub selector: String,
    pub process_role: String,
    pub candidate_sha256: String,
    pub release_tuple_v3_sha256: String,
    pub source_revision: String,
    pub workflow_run_id: String,
    pub namespace_sha256: String,
    pub ticket_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: ContextSignatureWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSignatureWire {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedRunContextWire {
    schema_version: String,
    context_id: String,
    scenario_id: String,
    selector: String,
    process_role: String,
    candidate_sha256: String,
    release_tuple_v3_sha256: String,
    source_revision: String,
    workflow_run_id: String,
    namespace_sha256: String,
    ticket_sha256: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

impl From<&RunContextWire> for UnsignedRunContextWire {
    fn from(value: &RunContextWire) -> Self {
        Self {
            schema_version: value.schema_version.clone(),
            context_id: value.context_id.clone(),
            scenario_id: value.scenario_id.clone(),
            selector: value.selector.clone(),
            process_role: value.process_role.clone(),
            candidate_sha256: value.candidate_sha256.clone(),
            release_tuple_v3_sha256: value.release_tuple_v3_sha256.clone(),
            source_revision: value.source_revision.clone(),
            workflow_run_id: value.workflow_run_id.clone(),
            namespace_sha256: value.namespace_sha256.clone(),
            ticket_sha256: value.ticket_sha256.clone(),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            nonce: value.nonce.clone(),
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<RunContextWire, QualificationRunContextError> {
    if bytes.is_empty() || bytes.len() > MAX_RUN_CONTEXT_BYTES {
        return Err(QualificationRunContextError::InvalidContext);
    }
    let context: RunContextWire =
        serde_json::from_slice(bytes).map_err(|_| QualificationRunContextError::InvalidContext)?;
    let canonical =
        serde_json::to_vec(&context).map_err(|_| QualificationRunContextError::InvalidContext)?;
    if canonical != bytes {
        return Err(QualificationRunContextError::InvalidContext);
    }
    Ok(context)
}

pub fn signing_payload(context: &RunContextWire) -> Result<Vec<u8>, QualificationRunContextError> {
    let canonical = serde_json::to_vec(&UnsignedRunContextWire::from(context))
        .map_err(|_| QualificationRunContextError::InvalidContext)?;
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
pub fn test_signing_payload(
    value: &serde_json::Value,
) -> Result<Vec<u8>, QualificationRunContextError> {
    let unsigned: UnsignedRunContextWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationRunContextError::InvalidContext)?;
    let canonical =
        serde_json::to_vec(&unsigned).map_err(|_| QualificationRunContextError::InvalidContext)?;
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
pub fn test_canonical_context(
    value: &serde_json::Value,
) -> Result<Vec<u8>, QualificationRunContextError> {
    let context: RunContextWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationRunContextError::InvalidContext)?;
    serde_json::to_vec(&context).map_err(|_| QualificationRunContextError::InvalidContext)
}
