use crate::credential::enrollment::{CredentialBindingDigest, CredentialEnrollmentError};
use zeroize::Zeroizing;

use super::super::CredentialServiceEpoch;

pub(super) fn take_vec(bytes: &[u8], at: &mut usize) -> Result<Vec<u8>, CredentialEnrollmentError> {
    let length = usize::from(u16::from_be_bytes(take(bytes, at)?));
    Ok(take_slice(bytes, at, length)?.to_vec())
}

pub(super) fn take_zeroizing_vec(
    bytes: &[u8],
    at: &mut usize,
) -> Result<Zeroizing<Vec<u8>>, CredentialEnrollmentError> {
    let length = usize::from(u16::from_be_bytes(take(bytes, at)?));
    Ok(Zeroizing::new(take_slice(bytes, at, length)?.to_vec()))
}

pub(super) fn number(bytes: &[u8], at: &mut usize) -> Result<u64, CredentialEnrollmentError> {
    Ok(u64::from_be_bytes(take(bytes, at)?))
}

pub(super) fn take_epoch(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialServiceEpoch, CredentialEnrollmentError> {
    CredentialServiceEpoch::from_bytes(take(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

pub(super) fn take_digest(
    bytes: &[u8],
    at: &mut usize,
) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured(take(bytes, at)?)
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

pub(super) fn take<const N: usize>(
    bytes: &[u8],
    at: &mut usize,
) -> Result<[u8; N], CredentialEnrollmentError> {
    take_slice(bytes, at, N)?
        .try_into()
        .map_err(|_| CredentialEnrollmentError::InvalidFrame)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    at: &mut usize,
    length: usize,
) -> Result<&'a [u8], CredentialEnrollmentError> {
    let end = at
        .checked_add(length)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    let value = bytes
        .get(*at..end)
        .ok_or(CredentialEnrollmentError::InvalidFrame)?;
    *at = end;
    Ok(value)
}
