use zeroize::Zeroizing;

use super::super::{
    CredentialServiceRegistrationBinding, CredentialServiceRegistrationError,
    CredentialServiceRegistrationSecret, CredentialServiceSessionAuthenticator,
    VerifiedCredentialServiceRegistration,
};
use super::{AcceptedCredentialServiceRegistration, CredentialServiceRegistrationInstall};

const MAGIC: &[u8; 8] = b"RNCRED01";
const VERSION: u16 = 1;
const HEADER: usize = 14;
const MAX: usize = 16 * 1024;

pub(crate) fn registration_install(
    auth: &CredentialServiceSessionAuthenticator,
    binding: CredentialServiceRegistrationBinding,
) -> Result<CredentialServiceRegistrationInstall, CredentialServiceRegistrationError> {
    let request = auth.authenticate_registration(binding)?.into_bytes();
    auth.with_registration_secret_for_install(|secret| {
        let payload_len = 1 + 4 + request.len() + secret.len();
        let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER + payload_len));
        header(&mut bytes, payload_len)?;
        bytes.push(1);
        bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(secret);
        Ok(CredentialServiceRegistrationInstall(bytes))
    })
}

pub(crate) fn accept_registration_install(
    bytes: &[u8],
    now_unix_millis: u64,
    policy: impl FnOnce(
        &CredentialServiceRegistrationBinding,
    ) -> Result<(), CredentialServiceRegistrationError>,
) -> Result<AcceptedCredentialServiceRegistration, CredentialServiceRegistrationError> {
    let payload = payload(bytes)?;
    if payload.first() != Some(&1) || payload.len() < 1 + 4 + 32 {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let request_len = u32::from_be_bytes(
        payload[1..5]
            .try_into()
            .map_err(|_| CredentialServiceRegistrationError::InvalidFrame)?,
    ) as usize;
    let request_end = 5_usize
        .checked_add(request_len)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    if request_end.checked_add(32) != Some(payload.len()) {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(&payload[request_end..]);
    let auth = CredentialServiceSessionAuthenticator::from_transported_secret(
        CredentialServiceRegistrationSecret(secret),
    );
    let request = auth.decode_registration(&payload[5..request_end])?;
    policy(request.binding())?;
    if request.binding().expires_at_unix_millis() <= now_unix_millis {
        return Err(CredentialServiceRegistrationError::Expired);
    }
    Ok(AcceptedCredentialServiceRegistration {
        authenticator: auth,
        verified: VerifiedCredentialServiceRegistration(request),
    })
}

fn header(out: &mut Vec<u8>, payload_len: usize) -> Result<(), CredentialServiceRegistrationError> {
    let total = HEADER
        .checked_add(payload_len)
        .ok_or(CredentialServiceRegistrationError::InvalidFrame)?;
    if total > MAX || payload_len > u32::MAX as usize {
        return Err(CredentialServiceRegistrationError::InvalidFrame);
    }
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&(payload_len as u32).to_be_bytes());
    Ok(())
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
