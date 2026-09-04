use super::{
    ContinuationBindingDigest, CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

impl CredentialEnrollmentMeasurementAuthority {
    /// Generates a new recovery continuation before any durable admission writes.
    /// Operation IDs, begin proofs and renderer input are not entropy sources.
    pub fn fresh_cleanup_continuation(
        &self,
    ) -> Result<ContinuationBindingDigest, CredentialEnrollmentError> {
        fresh_with(self, |bytes| {
            rand::rngs::OsRng.try_fill_bytes(bytes).map_err(|_| ())
        })
    }
}

fn fresh_with(
    authority: &CredentialEnrollmentMeasurementAuthority,
    fill: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
) -> Result<ContinuationBindingDigest, CredentialEnrollmentError> {
    let mut entropy = Zeroizing::new([0; 32]);
    fill(&mut entropy).map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
    if *entropy == [0; 32] {
        return Err(CredentialEnrollmentError::EntropyUnavailable);
    }
    let mut hash = Sha256::new();
    hash.update(b"runne/credential-cleanup-recovery/continuation/v1\0");
    hash.update(entropy.as_ref());
    authority.continuation_binding_digest(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CredentialEnrollmentAuthorityPair;

    #[test]
    fn recovery_entropy_produces_distinct_same_authority_continuations() {
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let first = measurements.fresh_cleanup_continuation().unwrap();
        let second = measurements.fresh_cleanup_continuation().unwrap();
        assert_ne!(first.digest(), second.digest());
        assert!(first.belongs_to(&measurements.seal));
        assert!(second.belongs_to(&measurements.seal));
    }

    #[test]
    fn recovery_entropy_failure_and_zero_fill_never_issue_a_continuation() {
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        assert!(matches!(
            fresh_with(&measurements, |bytes| {
                bytes.fill(19);
                Err(())
            }),
            Err(CredentialEnrollmentError::EntropyUnavailable)
        ));
        assert!(matches!(
            fresh_with(&measurements, |_| Ok(())),
            Err(CredentialEnrollmentError::EntropyUnavailable)
        ));
    }

    #[test]
    fn recovery_entropy_is_domain_separated_from_raw_bytes_and_ticket_digest() {
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let continuation = fresh_with(&measurements, |bytes| {
            bytes.fill(19);
            Ok(())
        })
        .unwrap();
        let mut ticket = Sha256::new();
        ticket.update(b"GOCODE_CREDENTIAL_TICKET_V2\0");
        ticket.update(32_u64.to_be_bytes());
        ticket.update([19; 32]);
        let ticket_digest: [u8; 32] = ticket.finalize().into();
        assert_ne!(continuation.digest().as_bytes(), [19; 32]);
        assert_ne!(continuation.digest().as_bytes(), ticket_digest);
    }
}
