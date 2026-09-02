use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::super::CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES;
use super::super::{CredentialServiceRegistrationError, CredentialServiceSessionAuthenticator};
use super::{CredentialServiceRuntimeEnvelope, VerifiedCredentialServiceRuntimePayload};

const MAGIC: &[u8; 8] = b"RNCRED01";
const VERSION: u16 = 1;
const HEADER: usize = 14;
const MAC_BYTES: usize = 32;
const MAX: usize = 16 * 1024;
const REQUEST_DOMAIN: &[u8] = b"gocode/macos-credential-service/runtime-request/v2\0";
const REPLY_DOMAIN: &[u8] = b"gocode/macos-credential-service/runtime-reply/v2\0";

pub(crate) fn authenticate_runtime_payload(
    auth: &CredentialServiceSessionAuthenticator,
    reply: bool,
    canonical_provider_frame: &[u8],
) -> Result<CredentialServiceRuntimeEnvelope, CredentialServiceRegistrationError> {
    let payload_len = canonical_provider_frame
        .len()
        .checked_add(MAC_BYTES)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    if canonical_provider_frame.is_empty()
        || canonical_provider_frame.len() > CREDENTIAL_SERVICE_RUNTIME_PROVIDER_FRAME_MAX_BYTES
        || HEADER + payload_len > MAX
    {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER + payload_len));
    header(&mut out, payload_len);
    out.extend_from_slice(canonical_provider_frame);
    let domain = if reply { REPLY_DOMAIN } else { REQUEST_DOMAIN };
    let mac = auth.runtime_mac(domain, canonical_provider_frame);
    out.extend_from_slice(&mac);
    Ok(CredentialServiceRuntimeEnvelope(out))
}

pub(crate) fn verify_runtime_payload(
    auth: &CredentialServiceSessionAuthenticator,
    bytes: &[u8],
    reply: bool,
) -> Result<VerifiedCredentialServiceRuntimePayload, CredentialServiceRegistrationError> {
    let payload = payload(bytes)?;
    if payload.len() <= MAC_BYTES {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let frame_end = payload.len() - MAC_BYTES;
    let domain = if reply { REPLY_DOMAIN } else { REQUEST_DOMAIN };
    let expected = auth.runtime_mac(domain, &payload[..frame_end]);
    if !bool::from(expected.ct_eq(&payload[frame_end..])) {
        return Err(CredentialServiceRegistrationError::AuthenticationFailed);
    }
    Ok(VerifiedCredentialServiceRuntimePayload(Zeroizing::new(
        payload[..frame_end].to_vec(),
    )))
}

fn header(out: &mut Vec<u8>, payload_len: usize) {
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&(payload_len as u32).to_be_bytes());
}

fn payload(bytes: &[u8]) -> Result<&[u8], CredentialServiceRegistrationError> {
    if bytes.len() < HEADER || bytes.len() > MAX || bytes.get(..8) != Some(MAGIC) {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    if bytes.get(8..10) != Some(&VERSION.to_be_bytes()) {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let length = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| CredentialServiceRegistrationError::InvalidFrame)?,
    ) as usize;
    if HEADER.checked_add(length) != Some(bytes.len()) {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    Ok(&bytes[HEADER..])
}
