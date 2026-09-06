use serde::{Deserialize, Serialize};

use crate::{MAX_FAULT_TICKET_BYTES, QualificationFaultError};

pub const SCHEMA_VERSION: &str = "runne/macos-xpc-dpk-fault-ticket/v1";
pub const SIGNATURE_DOMAIN: &[u8] = b"runne/macos-xpc-dpk-fault-ticket/v1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultTicketWire {
    pub schema_version: String,
    pub ticket_id: String,
    pub selector: String,
    pub process_role: String,
    pub candidate_sha256: String,
    pub release_tuple_v3_sha256: String,
    pub source_revision: String,
    pub workflow_run_id: String,
    pub namespace_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: FaultSignatureWire,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSignatureWire {
    pub algorithm: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedFaultTicketWire {
    schema_version: String,
    ticket_id: String,
    selector: String,
    process_role: String,
    candidate_sha256: String,
    release_tuple_v3_sha256: String,
    source_revision: String,
    workflow_run_id: String,
    namespace_sha256: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

impl From<&FaultTicketWire> for UnsignedFaultTicketWire {
    fn from(value: &FaultTicketWire) -> Self {
        Self {
            schema_version: value.schema_version.clone(),
            ticket_id: value.ticket_id.clone(),
            selector: value.selector.clone(),
            process_role: value.process_role.clone(),
            candidate_sha256: value.candidate_sha256.clone(),
            release_tuple_v3_sha256: value.release_tuple_v3_sha256.clone(),
            source_revision: value.source_revision.clone(),
            workflow_run_id: value.workflow_run_id.clone(),
            namespace_sha256: value.namespace_sha256.clone(),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            nonce: value.nonce.clone(),
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<FaultTicketWire, QualificationFaultError> {
    if bytes.is_empty() || bytes.len() > MAX_FAULT_TICKET_BYTES {
        return Err(QualificationFaultError::InvalidTicket);
    }
    let ticket: FaultTicketWire =
        serde_json::from_slice(bytes).map_err(|_| QualificationFaultError::InvalidTicket)?;
    let canonical =
        serde_json::to_vec(&ticket).map_err(|_| QualificationFaultError::InvalidTicket)?;
    if canonical != bytes {
        return Err(QualificationFaultError::InvalidTicket);
    }
    Ok(ticket)
}

pub fn signing_payload(ticket: &FaultTicketWire) -> Result<Vec<u8>, QualificationFaultError> {
    let canonical = serde_json::to_vec(&UnsignedFaultTicketWire::from(ticket))
        .map_err(|_| QualificationFaultError::InvalidTicket)?;
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
pub fn test_signing_payload(value: &serde_json::Value) -> Result<Vec<u8>, QualificationFaultError> {
    let unsigned: UnsignedFaultTicketWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationFaultError::InvalidTicket)?;
    let canonical =
        serde_json::to_vec(&unsigned).map_err(|_| QualificationFaultError::InvalidTicket)?;
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

#[cfg(test)]
pub fn test_canonical_ticket(
    value: &serde_json::Value,
) -> Result<Vec<u8>, QualificationFaultError> {
    let ticket: FaultTicketWire = serde_json::from_value(value.clone())
        .map_err(|_| QualificationFaultError::InvalidTicket)?;
    serde_json::to_vec(&ticket).map_err(|_| QualificationFaultError::InvalidTicket)
}
