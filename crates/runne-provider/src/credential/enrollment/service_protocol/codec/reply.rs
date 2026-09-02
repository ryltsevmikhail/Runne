use zeroize::Zeroizing;

use crate::credential::enrollment::CredentialEnrollmentError;

use super::super::{
    CredentialMaterial, CredentialServiceCorrelation, CredentialServiceDisposition,
    CredentialServiceEndpointRole, CredentialServiceReply, CredentialServiceReplyFrame,
    CredentialServiceRequestContext, CredentialServiceRequestKind,
    CredentialServiceRequestSequence,
};
use super::support::{take, take_epoch, take_vec};
use super::{byte, decode_role, epoch, frame, kind_role, payload, put_bytes, take_disposition};

pub(super) fn encode_reply(
    context: CredentialServiceRequestContext,
    value: CredentialServiceReply,
) -> Result<CredentialServiceReplyFrame, CredentialEnrollmentError> {
    if !reply_allowed(context.kind, &value) {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    encode_context(&mut bytes, context);
    encode_body(&mut bytes, value)?;
    let ceiling = if context.role == CredentialServiceEndpointRole::Runtime {
        super::CredentialServiceProtocolCodec::MAX_RUNTIME_PROVIDER_FRAME_BYTES
    } else {
        super::CredentialServiceProtocolCodec::MAX_FRAME_BYTES
    };
    Ok(CredentialServiceReplyFrame(frame(bytes, ceiling)?))
}

pub(super) fn decode_reply_for(
    bytes: &[u8],
    expected: CredentialServiceRequestContext,
    role: CredentialServiceEndpointRole,
) -> Result<CredentialServiceReply, CredentialEnrollmentError> {
    if expected.role != role {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let ceiling = if role == CredentialServiceEndpointRole::Runtime {
        super::CredentialServiceProtocolCodec::MAX_RUNTIME_PROVIDER_FRAME_BYTES
    } else {
        super::CredentialServiceProtocolCodec::MAX_FRAME_BYTES
    };
    let bytes = payload(bytes, ceiling)?;
    let mut at = super::HEADER;
    let actual = take_context(bytes, &mut at)?;
    if actual != expected || actual.role != role {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let value = decode_body(bytes, &mut at)?;
    if at != bytes.len() || !reply_allowed(expected.kind, &value) {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok(value)
}

fn encode_context(out: &mut Vec<u8>, value: CredentialServiceRequestContext) {
    kind_role(out, kind_code(value.kind), value.role);
    if let (Some(epoch_value), Some(sequence), Some(correlation)) =
        (value.epoch, value.sequence, value.correlation)
    {
        epoch(out, epoch_value);
        out.extend_from_slice(&sequence.get().to_be_bytes());
        out.extend_from_slice(&correlation.as_bytes());
    }
}

fn take_context(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialServiceRequestContext, CredentialEnrollmentError> {
    let kind = decode_kind(byte(bytes, at)?)?;
    let role = decode_role(byte(bytes, at)?)?;
    if kind == CredentialServiceRequestKind::RegistrationChallenge {
        if role != CredentialServiceEndpointRole::Desktop {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        return Ok(CredentialServiceRequestContext {
            role,
            kind,
            epoch: None,
            sequence: None,
            correlation: None,
        });
    }
    let epoch = take_epoch(bytes, at)?;
    let sequence = CredentialServiceRequestSequence::new(super::support::number(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    let correlation = CredentialServiceCorrelation::from_bytes(take(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)?;
    Ok(CredentialServiceRequestContext {
        role,
        kind,
        epoch: Some(epoch),
        sequence: Some(sequence),
        correlation: Some(correlation),
    })
}

fn encode_body(
    out: &mut Vec<u8>,
    value: CredentialServiceReply,
) -> Result<(), CredentialEnrollmentError> {
    match value {
        CredentialServiceReply::RegistrationChallenge {
            epoch: value,
            nonce,
        } => {
            out.push(11);
            epoch(out, value);
            out.extend_from_slice(&nonce);
        }
        CredentialServiceReply::Armed => out.push(12),
        CredentialServiceReply::Consumed => out.push(13),
        CredentialServiceReply::Metadata { present } => {
            out.push(14);
            out.push(u8::from(present));
        }
        CredentialServiceReply::Material(value) => {
            out.push(15);
            put_bytes(out, value.wire_bytes())?;
        }
        CredentialServiceReply::Rejected(value) => {
            out.push(16);
            super::disposition(out, value);
        }
    }
    Ok(())
}

fn decode_body(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialServiceReply, CredentialEnrollmentError> {
    match byte(bytes, at)? {
        11 => Ok(CredentialServiceReply::RegistrationChallenge {
            epoch: take_epoch(bytes, at)?,
            nonce: take(bytes, at)?,
        }),
        12 => Ok(CredentialServiceReply::Armed),
        13 => Ok(CredentialServiceReply::Consumed),
        14 => Ok(CredentialServiceReply::Metadata {
            present: match byte(bytes, at)? {
                0 => false,
                1 => true,
                _ => return Err(CredentialEnrollmentError::InvalidFrame),
            },
        }),
        15 => Ok(CredentialServiceReply::Material(
            CredentialMaterial::from_wire(take_vec(bytes, at)?)?,
        )),
        16 => Ok(CredentialServiceReply::Rejected(take_disposition(
            bytes, at,
        )?)),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}

fn reply_allowed(kind: CredentialServiceRequestKind, value: &CredentialServiceReply) -> bool {
    match value {
        CredentialServiceReply::Rejected(disposition) => rejection_allowed(kind, *disposition),
        _ => matches!(
            (kind, value),
            (
                CredentialServiceRequestKind::RegistrationChallenge,
                CredentialServiceReply::RegistrationChallenge { .. }
            ) | (
                CredentialServiceRequestKind::RuntimeMutationArm,
                CredentialServiceReply::Armed
            ) | (
                CredentialServiceRequestKind::WriterConsume,
                CredentialServiceReply::Consumed
            ) | (
                CredentialServiceRequestKind::MetadataReadback,
                CredentialServiceReply::Metadata { .. }
            ) | (
                CredentialServiceRequestKind::PointOfUseRead,
                CredentialServiceReply::Material(_)
            )
        ),
    }
}

fn rejection_allowed(
    kind: CredentialServiceRequestKind,
    disposition: CredentialServiceDisposition,
) -> bool {
    match disposition {
        CredentialServiceDisposition::Denied
        | CredentialServiceDisposition::Unavailable
        | CredentialServiceDisposition::Unsupported => true,
        CredentialServiceDisposition::SessionMissing { .. } => {
            kind != CredentialServiceRequestKind::RegistrationChallenge
        }
        CredentialServiceDisposition::Uncertain => {
            kind == CredentialServiceRequestKind::WriterConsume
        }
    }
}

fn kind_code(value: CredentialServiceRequestKind) -> u8 {
    match value {
        CredentialServiceRequestKind::RegistrationChallenge => 1,
        CredentialServiceRequestKind::RuntimeMutationArm => 2,
        CredentialServiceRequestKind::WriterConsume => 3,
        CredentialServiceRequestKind::MetadataReadback => 4,
        CredentialServiceRequestKind::PointOfUseRead => 5,
    }
}

fn decode_kind(value: u8) -> Result<CredentialServiceRequestKind, CredentialEnrollmentError> {
    match value {
        1 => Ok(CredentialServiceRequestKind::RegistrationChallenge),
        2 => Ok(CredentialServiceRequestKind::RuntimeMutationArm),
        3 => Ok(CredentialServiceRequestKind::WriterConsume),
        4 => Ok(CredentialServiceRequestKind::MetadataReadback),
        5 => Ok(CredentialServiceRequestKind::PointOfUseRead),
        _ => Err(CredentialEnrollmentError::InvalidFrame),
    }
}
