use serde::{Deserialize, Serialize};

use crate::{ProviderCredentialProviderV1, RunBinding};

use super::{
    MAX_QUALIFICATION_CASE_CONTROL_BYTES, QUALIFICATION_CASE_CONTROL_DOMAIN,
    QUALIFICATION_CASE_CONTROL_VERSION, QualificationCaseAction, QualificationCaseControlError,
    QualificationCaseControlReply, QualificationCaseControlRequest, QualificationCaseSelector,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    kind: String,
    domain: String,
    version: u8,
    role: String,
    workflow_run_id: String,
    source_revision: [u8; 20],
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    daemon_challenge: [u8; 32],
    session_id: [u8; 32],
    sequence: u64,
    selector: String,
    provider: String,
    action: String,
    expected_credential_revision: Option<u64>,
    run_not_after: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    kind: String,
    domain: String,
    version: u8,
    role: String,
    workflow_run_id: String,
    source_revision: [u8; 20],
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    daemon_challenge: [u8; 32],
    session_id: [u8; 32],
    sequence: u64,
    selector: String,
    provider: String,
    action: String,
    expected_credential_revision: Option<u64>,
    run_not_after: u64,
    expires_at: u64,
}

pub(super) fn encode_request(
    request: &QualificationCaseControlRequest,
) -> Result<Vec<u8>, QualificationCaseControlError> {
    canonical(&RequestWire::from(request))
}

pub(super) fn decode_request(
    bytes: &[u8],
) -> Result<QualificationCaseControlRequest, QualificationCaseControlError> {
    RequestWire::decode(canonical_decode(bytes)?)
}

pub(super) fn encode_reply(
    reply: &QualificationCaseControlReply,
) -> Result<Vec<u8>, QualificationCaseControlError> {
    canonical(&ReplyWire::from(reply))
}

pub(super) fn decode_reply(
    bytes: &[u8],
) -> Result<QualificationCaseControlReply, QualificationCaseControlError> {
    ReplyWire::decode(canonical_decode(bytes)?)
}

impl RequestWire {
    fn decode(self) -> Result<QualificationCaseControlRequest, QualificationCaseControlError> {
        header(
            &self.kind,
            &self.domain,
            self.version,
            &self.role,
            "case_request",
        )?;
        request_from_fields(
            self.workflow_run_id,
            self.source_revision,
            self.candidate_sha256,
            self.raw_v3_tuple_sha256,
            self.namespace_sha256,
            self.manifest_sha256,
            self.profile_sha256,
            self.daemon_challenge,
            self.session_id,
            self.sequence,
            self.selector,
            self.provider,
            self.action,
            self.expected_credential_revision,
            self.run_not_after,
        )
    }
}

impl ReplyWire {
    fn decode(self) -> Result<QualificationCaseControlReply, QualificationCaseControlError> {
        header(
            &self.kind,
            &self.domain,
            self.version,
            &self.role,
            "case_reply",
        )?;
        QualificationCaseControlReply::new(
            request_from_fields(
                self.workflow_run_id,
                self.source_revision,
                self.candidate_sha256,
                self.raw_v3_tuple_sha256,
                self.namespace_sha256,
                self.manifest_sha256,
                self.profile_sha256,
                self.daemon_challenge,
                self.session_id,
                self.sequence,
                self.selector,
                self.provider,
                self.action,
                self.expected_credential_revision,
                self.run_not_after,
            )?,
            self.expires_at,
        )
    }
}

impl From<&QualificationCaseControlRequest> for RequestWire {
    fn from(request: &QualificationCaseControlRequest) -> Self {
        let binding = request.binding();
        Self {
            kind: "case_request".into(),
            domain: QUALIFICATION_CASE_CONTROL_DOMAIN.into(),
            version: QUALIFICATION_CASE_CONTROL_VERSION,
            role: "request".into(),
            workflow_run_id: binding.workflow_run_id().into(),
            source_revision: binding.source_revision(),
            candidate_sha256: binding.candidate_sha256(),
            raw_v3_tuple_sha256: binding.raw_v3_tuple_sha256(),
            namespace_sha256: binding.namespace_sha256(),
            manifest_sha256: binding.manifest_sha256(),
            profile_sha256: binding.profile_sha256(),
            daemon_challenge: request.daemon_challenge(),
            session_id: request.session_id(),
            sequence: request.sequence(),
            selector: request.selector().as_str().into(),
            provider: request.provider().as_str().into(),
            action: request.action().as_str().into(),
            expected_credential_revision: request.expected_credential_revision(),
            run_not_after: request.run_not_after(),
        }
    }
}

impl From<&QualificationCaseControlReply> for ReplyWire {
    fn from(reply: &QualificationCaseControlReply) -> Self {
        let request = RequestWire::from(reply.request());
        Self {
            kind: "case_reply".into(),
            domain: request.domain,
            version: request.version,
            role: "reply".into(),
            workflow_run_id: request.workflow_run_id,
            source_revision: request.source_revision,
            candidate_sha256: request.candidate_sha256,
            raw_v3_tuple_sha256: request.raw_v3_tuple_sha256,
            namespace_sha256: request.namespace_sha256,
            manifest_sha256: request.manifest_sha256,
            profile_sha256: request.profile_sha256,
            daemon_challenge: request.daemon_challenge,
            session_id: request.session_id,
            sequence: request.sequence,
            selector: request.selector,
            provider: request.provider,
            action: request.action,
            expected_credential_revision: request.expected_credential_revision,
            run_not_after: request.run_not_after,
            expires_at: reply.expires_at(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn request_from_fields(
    workflow_run_id: String,
    source_revision: [u8; 20],
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    daemon_challenge: [u8; 32],
    session_id: [u8; 32],
    sequence: u64,
    selector: String,
    provider: String,
    action: String,
    expected_credential_revision: Option<u64>,
    run_not_after: u64,
) -> Result<QualificationCaseControlRequest, QualificationCaseControlError> {
    QualificationCaseControlRequest::new(
        RunBinding::new(
            &workflow_run_id,
            source_revision,
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
        )
        .map_err(|_| QualificationCaseControlError::InvalidMessage)?,
        daemon_challenge,
        session_id,
        sequence,
        QualificationCaseSelector::parse(&selector)?,
        ProviderCredentialProviderV1::parse(&provider)
            .map_err(|_| QualificationCaseControlError::InvalidMessage)?,
        QualificationCaseAction::parse(&action)?,
        expected_credential_revision,
        run_not_after,
    )
}

fn header(
    kind: &str,
    domain: &str,
    version: u8,
    role: &str,
    expected_kind: &str,
) -> Result<(), QualificationCaseControlError> {
    (kind == expected_kind
        && domain == QUALIFICATION_CASE_CONTROL_DOMAIN
        && version == QUALIFICATION_CASE_CONTROL_VERSION
        && ((expected_kind == "case_request" && role == "request")
            || (expected_kind == "case_reply" && role == "reply")))
        .then_some(())
        .ok_or(QualificationCaseControlError::InvalidMessage)
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, QualificationCaseControlError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| QualificationCaseControlError::InvalidMessage)?;
    (bytes.len() <= MAX_QUALIFICATION_CASE_CONTROL_BYTES)
        .then_some(bytes)
        .ok_or(QualificationCaseControlError::InvalidMessage)
}

fn canonical_decode<T: for<'a> Deserialize<'a> + Serialize>(
    bytes: &[u8],
) -> Result<T, QualificationCaseControlError> {
    if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_CASE_CONTROL_BYTES {
        return Err(QualificationCaseControlError::InvalidMessage);
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|_| QualificationCaseControlError::InvalidMessage)?;
    (canonical(&value)?.as_slice() == bytes)
        .then_some(value)
        .ok_or(QualificationCaseControlError::InvalidMessage)
}
