use sha2::{Digest, Sha256};

use crate::ApiPrincipalId;

const SUBJECT_DOMAIN: &[u8] = b"runne:protected:permission-control:stable-subject:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionControlSubjectErrorV1 {
    InvalidPrincipal,
}

/// Computes the exact stable subject digest used only alongside separately checked authority.
pub fn permission_control_stable_subject_digest_v1(
    principal: &ApiPrincipalId,
) -> Result<[u8; 32], PermissionControlSubjectErrorV1> {
    let value = principal.as_str();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PermissionControlSubjectErrorV1::InvalidPrincipal);
    }
    let mut hash = Sha256::new();
    hash.update(SUBJECT_DOMAIN);
    hash.update(value.as_bytes());
    Ok(hash.finalize().into())
}
