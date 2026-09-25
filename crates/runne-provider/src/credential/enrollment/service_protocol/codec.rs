use crate::credential::enrollment::{CredentialBindingDigest, CredentialEnrollmentError};

use super::request::CredentialRuntimeMutationBinding;
use super::{
    CredentialMaterial, CredentialMetadataReadbackAdmission, CredentialMutationGrant,
    CredentialPointOfUseReadAdmission, CredentialRuntimeMutationAdmission,
    CredentialServiceDisposition, CredentialServiceEndpointRole, CredentialServiceEpoch,
    CredentialServiceIngressRequest, CredentialServiceReply, CredentialServiceReplyFrame,
    CredentialServiceRequest, CredentialServiceRequestContext, CredentialServiceRequestFrame,
    CredentialWriterIngressRequest,
};
use zeroize::Zeroizing;

mod handoff;
mod mutation;
mod read;
mod reply;
mod runtime;
mod support;
use mutation::{mutation_binding, take_mutation_binding};
use read::{read_binding, take_read_binding};
use support::{take, take_digest, take_epoch, take_zeroizing_vec};

const HEADER: usize = 14;
const MAGIC: [u8; 8] = *b"RNCRED01";

/// Strict, explicit codec for the credential service XPC payload.
pub struct CredentialServiceProtocolCodec;

impl CredentialServiceProtocolCodec {
    /// Fixed protocol magic.
    pub const MAGIC: [u8; 8] = MAGIC;
    /// Fixed protocol version, encoded as big-endian `u16`.
    pub const VERSION: u16 = 2;
    /// Maximum complete frame size including the header.
    pub const MAX_FRAME_BYTES: usize = 16 * 1024;
    /// Largest provider frame that fits inside the runtime MAC envelope.
    pub const MAX_RUNTIME_PROVIDER_FRAME_BYTES: usize = Self::MAX_FRAME_BYTES - 14 - 32 - 32;
    /// Maximum credential material length.
    pub const MAX_CREDENTIAL_MATERIAL_BYTES: usize = CredentialMaterial::MAX_BYTES;
    /// Encodes one canonical request with its code-owned endpoint role.
    pub fn encode_request(
        value: CredentialServiceRequest,
    ) -> Result<CredentialServiceRequestFrame, CredentialEnrollmentError> {
        let role = value.endpoint_role();
        let mut payload = Zeroizing::new(Vec::new());
        match value {
            CredentialServiceRequest::RegistrationChallenge => {
                kind_role(&mut payload, 1, role);
            }
            CredentialServiceRequest::RuntimeMutationArm(value) => {
                kind_role(&mut payload, 2, role);
                mutation_binding(&mut payload, &value.0)?;
            }
            CredentialServiceRequest::WriterConsume(value) => {
                kind_role(
                    &mut payload,
                    if value.source_revision().is_some() {
                        7
                    } else {
                        3
                    },
                    role,
                );
                mutation_binding(&mut payload, value.binding())?;
                payload.extend_from_slice(value.grant().wire_bytes());
                put_bytes(&mut payload, value.material_bytes())?;
                if let Some(revision) = value.source_revision() {
                    payload.extend_from_slice(&revision);
                }
            }
            CredentialServiceRequest::MetadataReadback(value) => {
                kind_role(&mut payload, 4, role);
                read_binding(&mut payload, value.binding())?;
            }
            CredentialServiceRequest::PointOfUseRead(value) => {
                kind_role(&mut payload, 5, role);
                read_binding(&mut payload, value.binding())?;
                digest(&mut payload, value.receipt().digest());
            }
        }
        let ceiling = if role == CredentialServiceEndpointRole::Runtime {
            Self::MAX_RUNTIME_PROVIDER_FRAME_BYTES
        } else {
            Self::MAX_FRAME_BYTES
        };
        Ok(CredentialServiceRequestFrame(frame(payload, ceiling)?))
    }

    /// Decodes only the payload-free Desktop listener vocabulary.
    pub fn decode_desktop_request(
        bytes: &[u8],
    ) -> Result<CredentialServiceIngressRequest, CredentialEnrollmentError> {
        decode_request_for(bytes, CredentialServiceEndpointRole::Desktop)
    }

    /// Decodes only the authenticated runtime listener vocabulary.
    pub fn decode_runtime_request(
        bytes: &[u8],
    ) -> Result<CredentialServiceIngressRequest, CredentialEnrollmentError> {
        decode_request_for(bytes, CredentialServiceEndpointRole::Runtime)
    }

    /// Decodes only the authenticated one-shot writer listener vocabulary.
    pub fn decode_writer_request(
        bytes: &[u8],
    ) -> Result<CredentialServiceIngressRequest, CredentialEnrollmentError> {
        decode_request_for(bytes, CredentialServiceEndpointRole::Writer)
    }

    /// Encodes a reply bound to the exact request context and endpoint role.
    pub fn encode_reply(
        context: CredentialServiceRequestContext,
        value: CredentialServiceReply,
    ) -> Result<CredentialServiceReplyFrame, CredentialEnrollmentError> {
        reply::encode_reply(context, value)
    }

    /// Decodes a reply only for the exact Desktop request context.
    pub fn decode_desktop_reply(
        bytes: &[u8],
        expected: CredentialServiceRequestContext,
    ) -> Result<CredentialServiceReply, CredentialEnrollmentError> {
        reply::decode_reply_for(bytes, expected, CredentialServiceEndpointRole::Desktop)
    }

    /// Decodes a reply only for the exact runtime request context.
    pub fn decode_runtime_reply(
        bytes: &[u8],
        expected: CredentialServiceRequestContext,
    ) -> Result<CredentialServiceReply, CredentialEnrollmentError> {
        reply::decode_reply_for(bytes, expected, CredentialServiceEndpointRole::Runtime)
    }

    /// Decodes a reply only for the exact writer request context.
    pub fn decode_writer_reply(
        bytes: &[u8],
        expected: CredentialServiceRequestContext,
    ) -> Result<CredentialServiceReply, CredentialEnrollmentError> {
        reply::decode_reply_for(bytes, expected, CredentialServiceEndpointRole::Writer)
    }
}

fn decode_request_for(
    bytes: &[u8],
    expected_role: CredentialServiceEndpointRole,
) -> Result<CredentialServiceIngressRequest, CredentialEnrollmentError> {
    let mut at = HEADER;
    let ceiling = if expected_role == CredentialServiceEndpointRole::Runtime {
        CredentialServiceProtocolCodec::MAX_RUNTIME_PROVIDER_FRAME_BYTES
    } else {
        CredentialServiceProtocolCodec::MAX_FRAME_BYTES
    };
    let bytes = payload(bytes, ceiling)?;
    let kind = byte(bytes, &mut at)?;
    let role = decode_role(byte(bytes, &mut at)?)?;
    if role != expected_role {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let value = match kind {
        1 => CredentialServiceIngressRequest::RegistrationChallenge,
        2 => CredentialServiceIngressRequest::RuntimeMutationArm(
            CredentialRuntimeMutationAdmission(take_mutation_binding(bytes, &mut at)?),
        ),
        3 | 7 => {
            let binding = take_mutation_binding(bytes, &mut at)?;
            let grant = CredentialMutationGrant::from_wire(take(bytes, &mut at)?)?;
            let material = match take_zeroizing_vec(bytes, &mut at)? {
                value if value.is_empty() => None,
                value => Some(CredentialMaterial::from_wire(value)?),
            };
            let source_revision = if kind == 7 {
                Some(take(bytes, &mut at)?)
            } else {
                None
            };
            CredentialServiceIngressRequest::WriterConsume(
                CredentialWriterIngressRequest::from_wire(
                    binding,
                    grant,
                    material,
                    source_revision,
                )?,
            )
        }
        4 => CredentialServiceIngressRequest::MetadataReadback(
            CredentialMetadataReadbackAdmission::from_wire(take_read_binding(bytes, &mut at)?),
        ),
        5 => CredentialServiceIngressRequest::PointOfUseRead(
            CredentialPointOfUseReadAdmission::from_wire(
                take_read_binding(bytes, &mut at)?,
                super::CredentialDispatchEffectReceipt::from_wire(take_digest(bytes, &mut at)?),
            ),
        ),
        _ => return Err(CredentialEnrollmentError::InvalidFrame),
    };
    if at != bytes.len() || value.endpoint_role() != role {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok(value)
}

pub(crate) fn frame(
    payload: Zeroizing<Vec<u8>>,
    ceiling: usize,
) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
    if payload.len() + HEADER > ceiling {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + HEADER));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CredentialServiceProtocolCodec::VERSION.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}
pub(crate) fn payload(bytes: &[u8], ceiling: usize) -> Result<&[u8], CredentialEnrollmentError> {
    if bytes.len() < HEADER
        || bytes.len() > ceiling
        || bytes[..8] != MAGIC
        || bytes[8..10] != CredentialServiceProtocolCodec::VERSION.to_be_bytes()
    {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| CredentialEnrollmentError::InvalidFrame)?,
    ) as usize;
    if length + HEADER != bytes.len() {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok(bytes)
}
fn kind_role(out: &mut Vec<u8>, kind: u8, role: CredentialServiceEndpointRole) {
    out.push(kind);
    out.push(match role {
        CredentialServiceEndpointRole::Desktop => 1,
        CredentialServiceEndpointRole::Runtime => 2,
        CredentialServiceEndpointRole::Writer => 3,
    });
}
fn decode_role(value: u8) -> Result<CredentialServiceEndpointRole, CredentialEnrollmentError> {
    match value {
        1 => Ok(CredentialServiceEndpointRole::Desktop),
        2 => Ok(CredentialServiceEndpointRole::Runtime),
        3 => Ok(CredentialServiceEndpointRole::Writer),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
fn epoch(out: &mut Vec<u8>, value: CredentialServiceEpoch) {
    out.extend_from_slice(&value.as_bytes());
}
fn digest(out: &mut Vec<u8>, value: CredentialBindingDigest) {
    out.extend_from_slice(&value.as_bytes());
}
fn disposition(out: &mut Vec<u8>, value: CredentialServiceDisposition) {
    match value {
        CredentialServiceDisposition::SessionMissing { current_epoch } => {
            out.push(1);
            epoch(out, current_epoch);
        }
        CredentialServiceDisposition::Denied => out.push(2),
        CredentialServiceDisposition::Unavailable => out.push(3),
        CredentialServiceDisposition::Unsupported => out.push(4),
        CredentialServiceDisposition::Uncertain => out.push(5),
    }
}
fn take_disposition(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialServiceDisposition, CredentialEnrollmentError> {
    match byte(bytes, at)? {
        1 => Ok(CredentialServiceDisposition::SessionMissing {
            current_epoch: take_epoch(bytes, at)?,
        }),
        2 => Ok(CredentialServiceDisposition::Denied),
        3 => Ok(CredentialServiceDisposition::Unavailable),
        4 => Ok(CredentialServiceDisposition::Unsupported),
        5 => Ok(CredentialServiceDisposition::Uncertain),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), CredentialEnrollmentError> {
    let length = u16::try_from(value.len()).map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn byte(bytes: &[u8], at: &mut usize) -> Result<u8, CredentialEnrollmentError> {
    Ok(take::<1>(bytes, at)?[0])
}
