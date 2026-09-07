use crate::credential::enrollment::CredentialEnrollmentError;
use zeroize::Zeroizing;

use super::model::{
    COMMON_BYTES, ServiceQualificationCommon, ServiceQualificationRejectionCode,
    ServiceQualificationReplyFrame, ServiceQualificationRequest, ServiceQualificationRequestKind,
    ServiceQualificationRequestPayload,
};

const HEADER_BYTES: usize = 16;
const START_BODY_BYTES: usize = 12;
const PROGRESS_BODY_BYTES: usize = 8;
const MAX_RELEASE_BYTES: u32 = 524_300;
const MIN_RELEASE_BYTES: u32 = 13;
const CHUNK_BYTES: u16 = 8_192;
const MAX_CHUNK_COUNT: u16 = 65;
const MIN_ADMISSION_BYTES: u32 = 19;
const MAX_ADMISSION_BYTES: u32 = 8_192;

/// Strict `RNQSVC01` syntax codec for the disabled qualification ingress.
pub struct ServiceQualificationProtocolCodec;

impl ServiceQualificationProtocolCodec {
    /// Fixed qualification-profile magic.
    pub const MAGIC: [u8; 8] = *b"RNQSVC01";
    /// Fixed qualification-profile version.
    pub const VERSION: u16 = 1;
    /// Exact fixed header length.
    pub const HEADER_BYTES: usize = HEADER_BYTES;
    /// Exact fixed common-binding length.
    pub const COMMON_BYTES: usize = COMMON_BYTES;
    /// Largest complete V1 qualification frame.
    pub const MAX_FRAME_BYTES: usize =
        HEADER_BYTES + COMMON_BYTES + START_BODY_BYTES + CHUNK_BYTES as usize;

    /// Decodes only a complete, canonical request frame.
    pub fn decode_request(
        bytes: &[u8],
    ) -> Result<ServiceQualificationRequest, CredentialEnrollmentError> {
        let (kind, payload) = header(bytes)?;
        let common = common(payload)?;
        let request = match kind {
            ServiceQualificationRequestKind::Start => start(payload)?,
            ServiceQualificationRequestKind::Chunk => chunk(payload)?,
            ServiceQualificationRequestKind::Finalize => finalize(payload)?,
        };
        Ok(ServiceQualificationRequest::new(common, request))
    }

    /// Encodes only a canonical nonfinal progress reply for Start or Chunk.
    pub fn encode_progress(
        request: ServiceQualificationRequest,
        next_chunk_index: u16,
        received_release_bytes: u32,
    ) -> Result<ServiceQualificationReplyFrame, CredentialEnrollmentError> {
        if next_chunk_index > MAX_CHUNK_COUNT || received_release_bytes > MAX_RELEASE_BYTES {
            return Err(invalid());
        }
        let (common, kind) = request.into_reply_parts();
        let reply_kind = match kind {
            ServiceQualificationRequestKind::Start => 0x81,
            ServiceQualificationRequestKind::Chunk => 0x82,
            ServiceQualificationRequestKind::Finalize => return Err(invalid()),
        };
        let mut body = [0_u8; PROGRESS_BODY_BYTES];
        body[..2].copy_from_slice(&next_chunk_index.to_be_bytes());
        body[4..].copy_from_slice(&received_release_bytes.to_be_bytes());
        Ok(reply(reply_kind, common, &body))
    }

    /// Encodes only a canonical authenticated rejection matching the consumed request kind.
    pub fn encode_rejected(
        request: ServiceQualificationRequest,
        code: ServiceQualificationRejectionCode,
    ) -> ServiceQualificationReplyFrame {
        let (common, kind) = request.into_reply_parts();
        reply(0xff, common, &[kind.wire(), code.wire(), 0, 0])
    }
}

fn header(
    bytes: &[u8],
) -> Result<(ServiceQualificationRequestKind, &[u8]), CredentialEnrollmentError> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > ServiceQualificationProtocolCodec::MAX_FRAME_BYTES
        || bytes.get(..8) != Some(&ServiceQualificationProtocolCodec::MAGIC)
        || bytes.get(8..10) != Some(&ServiceQualificationProtocolCodec::VERSION.to_be_bytes())
        || bytes.get(10) != Some(&1)
    {
        return Err(invalid());
    }
    let kind = match bytes[11] {
        1 => ServiceQualificationRequestKind::Start,
        2 => ServiceQualificationRequestKind::Chunk,
        3 => ServiceQualificationRequestKind::Finalize,
        _ => return Err(invalid()),
    };
    let declared = u32_at(bytes, 12)? as usize;
    if declared.checked_add(HEADER_BYTES) != Some(bytes.len()) {
        return Err(invalid());
    }
    Ok((kind, &bytes[HEADER_BYTES..]))
}

fn common(payload: &[u8]) -> Result<ServiceQualificationCommon, CredentialEnrollmentError> {
    let common: [u8; COMMON_BYTES] = payload
        .get(..COMMON_BYTES)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    if common[22] >> 4 != 7 || common[24] >> 6 != 2 {
        return Err(invalid());
    }
    let nonzero = [
        &common[0..16],
        &common[16..32],
        &common[64..96],
        &common[96..128],
        &common[128..144],
        &common[168..184],
        &common[184..200],
        &common[208..240],
        &common[240..272],
        &common[272..304],
        &common[304..336],
    ];
    if nonzero
        .into_iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
    {
        return Err(invalid());
    }
    for offset in [32, 40, 48, 56, 144, 152, 160, 200, 336, 344] {
        if u64_at(&common, offset)? == 0 {
            return Err(invalid());
        }
    }
    let issued = u64_at(&common, 336)?;
    let expires = u64_at(&common, 344)?;
    if expires
        .checked_sub(issued)
        .filter(|duration| (1..=5_000).contains(duration))
        .is_none()
        || expires > u64_at(&common, 152)?
    {
        return Err(invalid());
    }
    Ok(ServiceQualificationCommon::from_wire(common))
}

fn start(payload: &[u8]) -> Result<ServiceQualificationRequestPayload, CredentialEnrollmentError> {
    if payload.len() != COMMON_BYTES + START_BODY_BYTES {
        return Err(invalid());
    }
    let release = u32_at(payload, COMMON_BYTES)?;
    let count = u16_at(payload, COMMON_BYTES + 6)?;
    if !(MIN_RELEASE_BYTES..=MAX_RELEASE_BYTES).contains(&release)
        || u16_at(payload, COMMON_BYTES + 4)? != CHUNK_BYTES
        || count != chunk_count(release)
        || !(MIN_ADMISSION_BYTES..=MAX_ADMISSION_BYTES)
            .contains(&u32_at(payload, COMMON_BYTES + 8)?)
    {
        return Err(invalid());
    }
    Ok(ServiceQualificationRequestPayload::Start {
        release_frame_len: release,
        chunk_bytes: CHUNK_BYTES,
        chunk_count: count,
        admission_bundle_len: u32_at(payload, COMMON_BYTES + 8)?,
    })
}

fn chunk(payload: &[u8]) -> Result<ServiceQualificationRequestPayload, CredentialEnrollmentError> {
    if payload.len() < COMMON_BYTES + START_BODY_BYTES {
        return Err(invalid());
    }
    let index = u16_at(payload, COMMON_BYTES)?;
    let count = u16_at(payload, COMMON_BYTES + 2)?;
    let offset = u32_at(payload, COMMON_BYTES + 4)?;
    let length = u16_at(payload, COMMON_BYTES + 8)?;
    if count == 0
        || count > MAX_CHUNK_COUNT
        || index >= count
        || length == 0
        || length > CHUNK_BYTES
        || (index + 1 < count && length != CHUNK_BYTES)
        || u16_at(payload, COMMON_BYTES + 10)? != 0
        || offset != u32::from(index) * u32::from(CHUNK_BYTES)
        || payload.len() != COMMON_BYTES + START_BODY_BYTES + usize::from(length)
        || (index + 1 == count
            && !implied_release_len(count, length)
                .is_some_and(|release| (MIN_RELEASE_BYTES..=MAX_RELEASE_BYTES).contains(&release)))
    {
        return Err(invalid());
    }
    Ok(ServiceQualificationRequestPayload::Chunk {
        chunk_index: index,
        chunk_count: count,
        offset,
        bytes: Zeroizing::new(payload[COMMON_BYTES + START_BODY_BYTES..].to_vec()),
    })
}

fn finalize(
    payload: &[u8],
) -> Result<ServiceQualificationRequestPayload, CredentialEnrollmentError> {
    if payload.len() < COMMON_BYTES + START_BODY_BYTES {
        return Err(invalid());
    }
    let release = u32_at(payload, COMMON_BYTES)?;
    let count = u16_at(payload, COMMON_BYTES + 4)?;
    let admission = u32_at(payload, COMMON_BYTES + 8)?;
    if !(MIN_RELEASE_BYTES..=MAX_RELEASE_BYTES).contains(&release)
        || count != chunk_count(release)
        || u16_at(payload, COMMON_BYTES + 6)? != 0
        || !(MIN_ADMISSION_BYTES..=MAX_ADMISSION_BYTES).contains(&admission)
        || payload.len() != COMMON_BYTES + START_BODY_BYTES + admission as usize
    {
        return Err(invalid());
    }
    Ok(ServiceQualificationRequestPayload::Finalize {
        release_frame_len: release,
        chunk_count: count,
        admission_bundle: Zeroizing::new(payload[COMMON_BYTES + START_BODY_BYTES..].to_vec()),
    })
}

fn reply(kind: u8, common: [u8; COMMON_BYTES], body: &[u8]) -> ServiceQualificationReplyFrame {
    let payload_len = COMMON_BYTES + body.len();
    let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + payload_len));
    bytes.extend_from_slice(&ServiceQualificationProtocolCodec::MAGIC);
    bytes.extend_from_slice(&ServiceQualificationProtocolCodec::VERSION.to_be_bytes());
    bytes.extend_from_slice(&[2, kind]);
    bytes.extend_from_slice(&(payload_len as u32).to_be_bytes());
    bytes.extend_from_slice(&common);
    bytes.extend_from_slice(body);
    ServiceQualificationReplyFrame::new(bytes)
}

fn chunk_count(release: u32) -> u16 {
    ((release - 1) / u32::from(CHUNK_BYTES) + 1) as u16
}

fn implied_release_len(count: u16, final_len: u16) -> Option<u32> {
    u32::from(count)
        .checked_sub(1)?
        .checked_mul(u32::from(CHUNK_BYTES))?
        .checked_add(u32::from(final_len))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, CredentialEnrollmentError> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, CredentialEnrollmentError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, CredentialEnrollmentError> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}

const fn invalid() -> CredentialEnrollmentError {
    CredentialEnrollmentError::InvalidFrame
}
