use super::{
    CREDENTIAL_SERVICE_MAX_FRAME_BYTES, CredentialServiceRegistrationBinding,
    CredentialServiceRegistrationError, CredentialServiceRegistrationRequest,
};

const MAGIC: &[u8; 8] = b"RNCRED01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 14;
const BINDING_BYTES: usize = 160;
const REQUEST_BYTES: usize = HEADER_BYTES + BINDING_BYTES + 32;
const ACK_BYTES: usize = HEADER_BYTES + 16 + 16 + 8 + 8 + 32;

pub(crate) fn encode_binding(value: &CredentialServiceRegistrationBinding) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BINDING_BYTES);
    bytes.extend_from_slice(&value.service_epoch);
    bytes.extend_from_slice(&value.protected_session_id);
    put_u64(&mut bytes, value.daemon_authority_generation);
    put_u64(&mut bytes, value.runtime_generation);
    put_u64(&mut bytes, value.supervisor_generation);
    put_u64(&mut bytes, value.installed_generation);
    bytes.extend_from_slice(&value.installation_owner);
    bytes.extend_from_slice(&value.release_binding);
    bytes.extend_from_slice(&value.challenge_nonce);
    put_u64(&mut bytes, value.join_attempt);
    put_u64(&mut bytes, value.expires_at_unix_millis);
    bytes
}
pub(crate) fn encode_request(value: &CredentialServiceRegistrationRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REQUEST_BYTES);
    header(&mut bytes, BINDING_BYTES + 32);
    bytes.extend(encode_binding(&value.binding));
    bytes.extend_from_slice(&value.mac);
    bytes
}
pub(crate) fn decode_request(
    bytes: &[u8],
) -> Result<CredentialServiceRegistrationRequest, CredentialServiceRegistrationError> {
    if bytes.len() > CREDENTIAL_SERVICE_MAX_FRAME_BYTES
        || bytes.len() != REQUEST_BYTES
        || !has_header(bytes, BINDING_BYTES + 32)
    {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut index = HEADER_BYTES;
    let binding = CredentialServiceRegistrationBinding::new(
        take(bytes, &mut index)?,
        take(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
        take(bytes, &mut index)?,
        take(bytes, &mut index)?,
        take(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
        take_u64(bytes, &mut index)?,
    )?;
    let mac = take(bytes, &mut index)?;
    if index != bytes.len() {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    Ok(CredentialServiceRegistrationRequest { binding, mac })
}
pub(crate) fn encode_ack(value: &super::CredentialServiceRegistrationAck) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACK_BYTES);
    header(&mut bytes, ACK_BYTES - HEADER_BYTES);
    bytes.extend_from_slice(&value.service_epoch);
    bytes.extend_from_slice(&value.protected_session_id);
    put_u64(&mut bytes, value.join_attempt);
    put_u64(&mut bytes, value.installed_generation);
    bytes.extend_from_slice(&value.mac);
    bytes
}
pub(crate) fn decode_ack(
    bytes: &[u8],
) -> Result<super::CredentialServiceRegistrationAck, CredentialServiceRegistrationError> {
    if bytes.len() > CREDENTIAL_SERVICE_MAX_FRAME_BYTES
        || bytes.len() != ACK_BYTES
        || !has_header(bytes, ACK_BYTES - HEADER_BYTES)
    {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut index = HEADER_BYTES;
    let ack = super::CredentialServiceRegistrationAck {
        service_epoch: take(bytes, &mut index)?,
        protected_session_id: take(bytes, &mut index)?,
        join_attempt: take_u64(bytes, &mut index)?,
        installed_generation: take_u64(bytes, &mut index)?,
        mac: take(bytes, &mut index)?,
    };
    if index != bytes.len() {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    Ok(ack)
}
fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn header(bytes: &mut Vec<u8>, payload_length: usize) {
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&(payload_length as u32).to_be_bytes());
}
fn has_header(bytes: &[u8], payload_length: usize) -> bool {
    bytes.get(..8) == Some(MAGIC)
        && bytes.get(8..10) == Some(&VERSION.to_be_bytes())
        && bytes.get(10..14) == Some(&(payload_length as u32).to_be_bytes())
}
fn take_u64(bytes: &[u8], index: &mut usize) -> Result<u64, CredentialServiceRegistrationError> {
    Ok(u64::from_be_bytes(take(bytes, index)?))
}
fn take<const N: usize>(
    bytes: &[u8],
    index: &mut usize,
) -> Result<[u8; N], CredentialServiceRegistrationError> {
    let end = index
        .checked_add(N)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    let value = bytes
        .get(*index..end)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    *index = end;
    value
        .try_into()
        .map_err(|_| CredentialServiceRegistrationError::InvalidFrame)
}
