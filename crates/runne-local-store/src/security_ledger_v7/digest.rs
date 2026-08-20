use crate::{CommandRef, OutcomeRef};
use sha2::Digest;

pub fn command(bytes: &[u8]) -> CommandRef {
    CommandRef::new(hash(b"gocode/local-store/mutation-command/v7\0", bytes))
        .expect("domain-separated SHA-256 is nonzero")
}

pub fn outcome(bytes: &[u8]) -> OutcomeRef {
    OutcomeRef::new(hash(b"gocode/local-store/mutation-outcome/v7\0", bytes))
        .expect("domain-separated SHA-256 is nonzero")
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(domain);
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}
