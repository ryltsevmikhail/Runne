use crate::{Digest, Path, SecurityStateError, Sha256};

pub fn database_identity(path: &Path) -> Result<[u8; 32], SecurityStateError> {
    Ok(digest(
        b"runne/security/database-identity/v1\0",
        path.canonicalize()
            .map_err(|_| SecurityStateError::AdmissionFailed)?
            .to_string_lossy()
            .as_bytes(),
    ))
}
pub fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}
pub fn hex(value: &[u8; 32]) -> String {
    use std::fmt::Write;
    value
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("string");
            output
        })
}
