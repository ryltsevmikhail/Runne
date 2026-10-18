use super::validation::{MAX_FRAME_BYTES, validate_context, validate_now, validate_payload};
use super::{
    AuthenticatedPermissionControlFrameV1 as Authenticated, PermissionControlAuthenticatorV1,
    PermissionControlContextV1 as Context, PermissionControlDirectionV1 as Direction,
    PermissionControlErrorV1 as Error, PermissionControlPayloadV1 as Payload,
    PermissionControlPhaseV1 as Phase, PermissionControlPurposeV1 as Purpose,
};

const MAC_BYTES: usize = 32;
const PREFIX_BYTES: usize = 4;

pub(super) fn issue(
    auth: &PermissionControlAuthenticatorV1,
    context: Context,
    sequence: u64,
    direction: Direction,
    payload: Payload,
) -> Result<Vec<u8>, Error> {
    if sequence == 0 {
        return Err(Error::SequenceMismatch);
    }
    if payload.direction() != direction {
        return Err(Error::DirectionMismatch);
    }
    validate_context(&context, payload.phase())?;
    validate_payload(auth.purpose, &payload, &context)?;
    let unsigned =
        super::encode::encode_unsigned(auth.purpose, direction, sequence, &context, &payload)?;
    let len = PREFIX_BYTES
        .checked_add(unsigned.len())
        .and_then(|n| n.checked_add(MAC_BYTES))
        .filter(|n| *n <= MAX_FRAME_BYTES)
        .ok_or(Error::InvalidContract)?;
    let mut frame = Vec::with_capacity(len);
    frame.extend_from_slice(
        &(u32::try_from(len).map_err(|_| Error::InvalidContract)?).to_be_bytes(),
    );
    frame.extend_from_slice(&unsigned);
    let proof = auth.mac(&frame);
    frame.extend_from_slice(&proof);
    Ok(frame)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authenticate(
    auth: &PermissionControlAuthenticatorV1,
    bytes: &[u8],
    expected_context: &Context,
    expected_purpose: Purpose,
    expected_phase: Phase,
    expected_direction: Direction,
    previous_sequence: u64,
    now: u64,
) -> Result<Authenticated, Error> {
    if bytes.len() > MAX_FRAME_BYTES || bytes.len() < 4 + 8 + 3 + 8 + MAC_BYTES {
        return Err(Error::MalformedFrame);
    }
    let declared =
        u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::MalformedFrame)?) as usize;
    if declared != bytes.len() || declared > MAX_FRAME_BYTES {
        return Err(Error::MalformedFrame);
    }
    let mac_at = bytes.len() - MAC_BYTES;
    if !auth.authenticate_mac(&bytes[..mac_at], &bytes[mac_at..]) {
        return Err(Error::AuthenticationFailed);
    }
    if expected_purpose != auth.purpose {
        return Err(Error::PurposeMismatch);
    }
    let decoded = super::decode::decode_unsigned(&bytes[PREFIX_BYTES..mac_at])?;
    if decoded.purpose != auth.purpose {
        return Err(Error::PurposeMismatch);
    }
    if decoded.payload.phase() != expected_phase {
        return Err(Error::PhaseMismatch);
    }
    if decoded.direction != expected_direction || decoded.payload.direction() != expected_direction
    {
        return Err(Error::DirectionMismatch);
    }
    validate_context(&decoded.context, decoded.payload.phase())?;
    validate_payload(decoded.purpose, &decoded.payload, &decoded.context)?;
    if &decoded.context != expected_context {
        return Err(Error::ContextMismatch);
    }
    validate_now(&decoded.context, now)?;
    let next = previous_sequence
        .checked_add(1)
        .ok_or(Error::SequenceMismatch)?;
    if decoded.sequence != next {
        return Err(Error::SequenceMismatch);
    }
    Ok(Authenticated {
        purpose: decoded.purpose,
        direction: decoded.direction,
        sequence: decoded.sequence,
        context: decoded.context,
        payload: decoded.payload,
    })
}
