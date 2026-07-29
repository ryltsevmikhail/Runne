//! Versioned, bounded, deterministic durable snapshot codecs.

use std::str::FromStr;
use std::sync::OnceLock;

use gocode_api::{ApiActor, ApiPrincipalId, OpenCodeSessionInfo, ResponseSeed};
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_opencode_compat::{SessionBindingContext, SessionCreateFingerprint};
use jsonschema::JSONSchema;

/// Maximum bytes for either durable snapshot.
pub const MAX_SNAPSHOT_BYTES: usize = 65_536;
/// The sole supported snapshot encoding version.
pub const CODEC_VERSION: u16 = 1;

static SESSION_SCHEMA: OnceLock<Result<JSONSchema, String>> = OnceLock::new();

/// Snapshot codec failure. All variants are fail-closed at the adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The snapshot is too short for its declared representation.
    Truncated,
    /// The version has no decoder.
    UnsupportedVersion,
    /// The snapshot exceeds its bounded representation.
    Oversized,
    /// A declared length is not valid.
    InvalidLength,
    /// A field is not valid UTF-8 or its value violates its contract.
    InvalidField,
    /// The JSON response does not satisfy its wire schema.
    InvalidResponse,
    /// The authoritative schema could not be compiled.
    SchemaUnavailable,
}

/// Encodes a complete immutable binding context.
pub fn encode_context(context: &SessionBindingContext) -> Result<Vec<u8>, CodecError> {
    let mut output = Vec::new();
    put_string(&mut output, &context.conversation_id.to_string())?;
    put_string(&mut output, &context.workspace_id.to_string())?;
    put_string(&mut output, &context.command_id.to_string())?;
    put_string(&mut output, context.idempotency_key.as_str())?;
    output.extend_from_slice(context.request_fingerprint.as_bytes());
    put_optional_string(&mut output, context.title.as_deref())?;
    put_string(&mut output, context.principal.as_str())?;
    put_string(&mut output, context.actor.as_str())?;
    put_string(&mut output, &context.response_seed.project_id)?;
    put_string(&mut output, &context.response_seed.directory)?;
    put_optional_string(&mut output, context.response_seed.path.as_deref())?;
    put_string(&mut output, &context.response_seed.version)?;
    put_optional_string(&mut output, context.response_seed.workspace_id.as_deref())?;
    bounded(&output)?;
    Ok(output)
}

/// Decodes a complete immutable binding context without synthesizing fields.
pub fn decode_context(bytes: &[u8]) -> Result<SessionBindingContext, CodecError> {
    bounded(bytes)?;
    let mut input = Input::new(bytes);
    let conversation_id =
        ConversationId::from_str(input.string()?.as_str()).map_err(|_| CodecError::InvalidField)?;
    let workspace_id =
        WorkspaceId::from_str(input.string()?.as_str()).map_err(|_| CodecError::InvalidField)?;
    let command_id =
        CommandId::from_str(input.string()?.as_str()).map_err(|_| CodecError::InvalidField)?;
    let idempotency_key =
        IdempotencyKey::new(input.string()?).map_err(|_| CodecError::InvalidField)?;
    let fingerprint = input.fixed_32()?;
    let title = input.optional_string()?;
    let principal = ApiPrincipalId::new(input.string()?).map_err(|_| CodecError::InvalidField)?;
    let actor = ApiActor::new(input.string()?).map_err(|_| CodecError::InvalidField)?;
    let project_id = input.string()?;
    let directory = input.string()?;
    let path = input.optional_string()?;
    let version = input.string()?;
    let workspace_seed = input.optional_string()?;
    if !input.finished() {
        return Err(CodecError::InvalidLength);
    }
    Ok(SessionBindingContext {
        conversation_id,
        workspace_id,
        command_id,
        idempotency_key,
        request_fingerprint: SessionCreateFingerprint::from_bytes(fingerprint),
        title,
        principal,
        actor,
        response_seed: ResponseSeed {
            project_id,
            directory,
            path,
            version,
            workspace_id: workspace_seed,
        },
    })
}

/// Encodes a validated wire response using stable JSON serialization.
pub fn encode_response(response: &OpenCodeSessionInfo) -> Result<Vec<u8>, CodecError> {
    let json = serde_json::to_vec(response.as_value()).map_err(|_| CodecError::InvalidResponse)?;
    bounded(&json)?;
    let schema = SESSION_SCHEMA
        .get_or_init(load_schema)
        .as_ref()
        .map_err(|_| CodecError::SchemaUnavailable)?;
    OpenCodeSessionInfo::from_slice(&json, schema).map_err(|_| CodecError::InvalidResponse)?;
    Ok(json)
}

/// Decodes and re-validates a response against the authoritative schema.
pub fn decode_response(bytes: &[u8]) -> Result<OpenCodeSessionInfo, CodecError> {
    bounded(bytes)?;
    let schema = SESSION_SCHEMA
        .get_or_init(load_schema)
        .as_ref()
        .map_err(|_| CodecError::SchemaUnavailable)?;
    let response =
        OpenCodeSessionInfo::from_slice(bytes, schema).map_err(|_| CodecError::InvalidResponse)?;
    if encode_response(&response)? != bytes {
        return Err(CodecError::InvalidResponse);
    }
    Ok(response)
}

fn load_schema() -> Result<JSONSchema, String> {
    let value = serde_json::from_str(include_str!(
        "../../../docs/schemas/session-info-v1.schema.json"
    ))
    .map_err(|e| e.to_string())?;
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&value)
        .map_err(|e| e.to_string())
}

fn bounded(bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        Err(CodecError::Oversized)
    } else {
        Ok(())
    }
}
fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), CodecError> {
    let len = u32::try_from(value.len()).map_err(|_| CodecError::Oversized)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    bounded(output)
}
fn put_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), CodecError> {
    match value {
        Some(value) => {
            output.push(1);
            put_string(output, value)
        }
        None => {
            output.push(0);
            bounded(output)
        }
    }
}
struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .at
            .checked_add(length)
            .ok_or(CodecError::InvalidLength)?;
        let out = self.bytes.get(self.at..end).ok_or(CodecError::Truncated)?;
        self.at = end;
        Ok(out)
    }
    fn string(&mut self) -> Result<String, CodecError> {
        let b = self.take(4)?;
        let length = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let raw = self.take(length)?;
        String::from_utf8(raw.to_vec()).map_err(|_| CodecError::InvalidField)
    }
    fn optional_string(&mut self) -> Result<Option<String>, CodecError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(CodecError::InvalidField),
        }
    }
    fn fixed_32(&mut self) -> Result<[u8; 32], CodecError> {
        self.take(32)?.try_into().map_err(|_| CodecError::Truncated)
    }
    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
    use gocode_opencode_compat::SessionCreateFingerprint;

    fn context() -> SessionBindingContext {
        SessionBindingContext {
            conversation_id: ConversationId::from_str("018f2e3a-7000-7000-8000-000000000001")
                .unwrap(),
            workspace_id: WorkspaceId::from_str("018f2e3a-7000-7000-8000-000000000002").unwrap(),
            command_id: CommandId::from_str("018f2e3a-7000-7000-8000-000000000003").unwrap(),
            idempotency_key: IdempotencyKey::new("request-a").unwrap(),
            request_fingerprint: SessionCreateFingerprint::from_bytes([7; 32]),
            title: Some("A title".to_owned()),
            principal: ApiPrincipalId::new("principal-a").unwrap(),
            actor: ApiActor::new("actor-a").unwrap(),
            response_seed: ResponseSeed {
                project_id: "project-a".to_owned(),
                directory: "/tmp".to_owned(),
                path: None,
                version: "1.0".to_owned(),
                workspace_id: None,
            },
        }
    }

    fn response() -> OpenCodeSessionInfo {
        let schema = SESSION_SCHEMA.get_or_init(load_schema).as_ref().unwrap();
        OpenCodeSessionInfo::from_json(
            serde_json::json!({"id":"session-a","slug":"a","projectID":"project-a","directory":"/tmp","title":"A title","version":"1.0","time":{"created":1,"updated":1}}),
            schema,
        ).unwrap()
    }

    #[test]
    fn context_golden_is_deterministic_and_rejects_malformed_input() {
        let value = context();
        let first = encode_context(&value).unwrap();
        assert_eq!(first, encode_context(&value).unwrap());
        assert_eq!(decode_context(&first), Ok(value));
        assert_eq!(
            bytes_to_hex(&first),
            "0000002430313866326533612d373030302d373030302d383030302d3030303030303030303030310000002430313866326533612d373030302d373030302d383030302d3030303030303030303030320000002430313866326533612d373030302d373030302d383030302d30303030303030303030303300000009726571756573742d610707070707070707070707070707070707070707070707070707070707070707010000000741207469746c650000000b7072696e636970616c2d61000000076163746f722d610000000970726f6a6563742d61000000042f746d700000000003312e3000"
        );
        assert_eq!(
            decode_context(&first[..first.len() - 1]),
            Err(CodecError::Truncated)
        );
        let mut invalid_utf8 = first.clone();
        invalid_utf8[4] = 0xff;
        assert_eq!(decode_context(&invalid_utf8), Err(CodecError::InvalidField));
        assert_eq!(
            decode_context(&vec![0; MAX_SNAPSHOT_BYTES + 1]),
            Err(CodecError::Oversized)
        );
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn response_golden_is_canonical_and_rejects_noncanonical_bytes() {
        let response = response();
        let bytes = encode_response(&response).unwrap();
        assert_eq!(bytes, encode_response(&response).unwrap());
        assert_eq!(decode_response(&bytes), Ok(response));
        assert_eq!(bytes, br#"{"directory":"/tmp","id":"session-a","projectID":"project-a","slug":"a","time":{"created":1,"updated":1},"title":"A title","version":"1.0"}"#);
        let mut whitespace = bytes.clone();
        whitespace.push(b' ');
        assert_eq!(
            decode_response(&whitespace),
            Err(CodecError::InvalidResponse)
        );
        assert_eq!(decode_response(br#"{"id":"session-a","directory":"/tmp","projectID":"project-a","slug":"a","time":{"created":1,"updated":1},"title":"A title","version":"1.0"}"#), Err(CodecError::InvalidResponse));
        assert_eq!(
            decode_response(&vec![b'x'; MAX_SNAPSHOT_BYTES + 1]),
            Err(CodecError::Oversized)
        );
    }
}
