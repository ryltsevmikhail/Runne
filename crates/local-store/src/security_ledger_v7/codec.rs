use crate::{BoundedCanonicalId, SecurityStateError};

pub(super) const VERSION: u8 = 1;
pub(super) const MAX_VALUE: usize = 16_384;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_MESSAGE_TEXT_BYTES: usize = 64 * 1024;

pub(super) const fn take<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], SecurityStateError> {
    if length > input.len() || length > MAX_VALUE {
        return Err(SecurityStateError::InvalidTransition);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}
pub(super) fn byte(input: &mut &[u8]) -> Result<u8, SecurityStateError> {
    Ok(*take(input, 1)?
        .first()
        .ok_or(SecurityStateError::InvalidTransition)?)
}
pub(super) fn u64(input: &mut &[u8]) -> Result<u64, SecurityStateError> {
    Ok(u64::from_be_bytes(
        take(input, 8)?
            .try_into()
            .map_err(|_| SecurityStateError::InvalidTransition)?,
    ))
}
pub(super) fn fixed<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], SecurityStateError> {
    take(input, N)?
        .try_into()
        .map_err(|_| SecurityStateError::InvalidTransition)
}
pub(super) fn text(input: &mut &[u8]) -> Result<String, SecurityStateError> {
    let length = usize::from(u16::from_be_bytes(
        take(input, 2)?
            .try_into()
            .map_err(|_| SecurityStateError::InvalidTransition)?,
    ));
    let value = std::str::from_utf8(take(input, length)?)
        .map_err(|_| SecurityStateError::InvalidTransition)?;
    (!value.is_empty() && value.len() <= MAX_VALUE)
        .then(|| value.to_owned())
        .ok_or(SecurityStateError::InvalidTransition)
}
pub(super) fn display_name(input: &mut &[u8]) -> Result<String, SecurityStateError> {
    let value = text(input)?;
    crate::recent_roots::valid_display_name(&value)
        .then_some(value)
        .ok_or(SecurityStateError::InvalidTransition)
}
pub(super) fn message_text(input: &mut &[u8]) -> Result<String, SecurityStateError> {
    let length = usize::try_from(u32::from_be_bytes(
        take(input, 4)?
            .try_into()
            .map_err(|_| SecurityStateError::InvalidTransition)?,
    ))
    .map_err(|_| SecurityStateError::InvalidTransition)?;
    let value = std::str::from_utf8(take_message(input, length)?)
        .map_err(|_| SecurityStateError::InvalidTransition)?;
    (!value.is_empty() && value.len() <= MAX_MESSAGE_TEXT_BYTES)
        .then(|| value.to_owned())
        .ok_or(SecurityStateError::InvalidTransition)
}
pub(super) fn id(input: &mut &[u8]) -> Result<BoundedCanonicalId, SecurityStateError> {
    BoundedCanonicalId::parse(text(input)?.as_bytes())
}
pub(super) fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), SecurityStateError> {
    let length = u16::try_from(value.len()).map_err(|_| SecurityStateError::InvalidTransition)?;
    if value.is_empty() || value.len() > MAX_VALUE {
        return Err(SecurityStateError::InvalidTransition);
    }
    output.extend(length.to_be_bytes());
    output.extend(value.as_bytes());
    Ok(())
}
pub(super) fn put_display_name(
    output: &mut Vec<u8>,
    value: &str,
) -> Result<(), SecurityStateError> {
    if value.len() > MAX_DISPLAY_NAME_BYTES || !crate::recent_roots::valid_display_name(value) {
        return Err(SecurityStateError::InvalidTransition);
    }
    put_text(output, value)
}
pub(super) fn put_message_text(
    output: &mut Vec<u8>,
    value: &str,
) -> Result<(), SecurityStateError> {
    if value.is_empty() || value.len() > MAX_MESSAGE_TEXT_BYTES {
        return Err(SecurityStateError::InvalidTransition);
    }
    output.extend(
        u32::try_from(value.len())
            .map_err(|_| SecurityStateError::InvalidTransition)?
            .to_be_bytes(),
    );
    output.extend(value.as_bytes());
    Ok(())
}
pub(super) fn put_id(
    output: &mut Vec<u8>,
    value: &BoundedCanonicalId,
) -> Result<(), SecurityStateError> {
    put_text(
        output,
        std::str::from_utf8(value.as_bytes()).map_err(|_| SecurityStateError::InvalidIdentity)?,
    )
}
pub(super) fn finish(input: &[u8]) -> Result<(), SecurityStateError> {
    input
        .is_empty()
        .then_some(())
        .ok_or(SecurityStateError::InvalidTransition)
}
const fn take_message<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], SecurityStateError> {
    if length > input.len() || length > MAX_MESSAGE_TEXT_BYTES {
        return Err(SecurityStateError::InvalidTransition);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}
