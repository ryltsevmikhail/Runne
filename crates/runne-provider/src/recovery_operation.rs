use crate::{
    ProviderRecoveryBinding, ProviderRecoveryError, ProviderRecoveryOperation, RemoteResponseId,
};

/// Opaque nonce metadata for one fresh remote operation.
///
/// The nonce is useful only when a trusted persistence layer has an exact issued row for it.
/// Its constructor does not create authority; durable writers must consume and validate the
/// corresponding current-owner record before accepting any observation.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteOperationProof {
    binding: ProviderRecoveryBinding,
    operation: ProviderRecoveryOperation,
    response_id_digest: [u8; 32],
    nonce: [u8; 16],
    expires_at_unix_seconds: u64,
}

impl ProviderRemoteOperationProof {
    /// Creates proof metadata for transport handoff; the nonce must already be store-issued.
    pub fn new(
        binding: ProviderRecoveryBinding,
        operation: ProviderRecoveryOperation,
        response_id: &RemoteResponseId,
        nonce: [u8; 16],
        expires_at_unix_seconds: u64,
    ) -> Result<Self, ProviderRecoveryError> {
        if nonce == [0; 16] || expires_at_unix_seconds == 0 {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        use sha2::Digest as _;
        let response_id_digest =
            <[u8; 32]>::from(sha2::Sha256::digest(response_id.as_str().as_bytes()));
        Ok(Self {
            binding,
            operation,
            response_id_digest,
            nonce,
            expires_at_unix_seconds,
        })
    }

    /// Returns the exact historical attempt binding.
    pub const fn binding(&self) -> ProviderRecoveryBinding {
        self.binding
    }
    /// Returns the single operation authorized by this nonce.
    pub const fn operation(&self) -> ProviderRecoveryOperation {
        self.operation
    }
    /// Returns the digest of the exact remote response identifier.
    pub const fn response_id_digest(&self) -> [u8; 32] {
        self.response_id_digest
    }
    /// Returns the one-use database nonce.
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    /// Returns the issuer's expiry timestamp in Unix seconds.
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Checks the request tuple before a transport attempt.
    pub fn matches(
        &self,
        binding: ProviderRecoveryBinding,
        operation: ProviderRecoveryOperation,
        response_id: &RemoteResponseId,
    ) -> bool {
        use sha2::Digest as _;
        self.binding == binding
            && self.operation == operation
            && self.response_id_digest
                == <[u8; 32]>::from(sha2::Sha256::digest(response_id.as_str().as_bytes()))
    }
}

impl core::fmt::Debug for ProviderRemoteOperationProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderRemoteOperationProof")
            .field("operation", &self.operation)
            .field("nonce", &"[redacted]")
            .field("response_id_digest", &"[redacted]")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ProviderRecoveryBinding {
        ProviderRecoveryBinding::new(
            crate::TaskRunId::from_bytes([1; 16]),
            crate::AttemptId::from_bytes([2; 16]),
            crate::DispatchAttemptId::from_bytes([3; 16]),
            [4; 32],
        )
        .unwrap()
    }

    #[test]
    fn operation_proof_binds_attempt_operation_and_remote_response() {
        let id = RemoteResponseId::new("resp_fixture").unwrap();
        let proof = ProviderRemoteOperationProof::new(
            binding(),
            ProviderRecoveryOperation::StatusCheck,
            &id,
            [9; 16],
            100,
        )
        .unwrap();
        assert!(proof.matches(binding(), ProviderRecoveryOperation::StatusCheck, &id));
        assert!(!proof.matches(binding(), ProviderRecoveryOperation::RemoteCancel, &id));
        assert!(!proof.matches(
            binding(),
            ProviderRecoveryOperation::StatusCheck,
            &RemoteResponseId::new("resp_other").unwrap(),
        ));
        let foreign = ProviderRecoveryBinding::new(
            crate::TaskRunId::from_bytes([8; 16]),
            crate::AttemptId::from_bytes([2; 16]),
            crate::DispatchAttemptId::from_bytes([3; 16]),
            [4; 32],
        )
        .unwrap();
        assert!(!proof.matches(foreign, ProviderRecoveryOperation::StatusCheck, &id));
    }

    #[test]
    fn operation_proof_debug_hides_nonce_and_remote_identity() {
        let id = RemoteResponseId::new("resp_private_fixture").unwrap();
        let proof = ProviderRemoteOperationProof::new(
            binding(),
            ProviderRecoveryOperation::RemoteCancel,
            &id,
            [0xAB; 16],
            100,
        )
        .unwrap();
        let output = format!("{proof:?}");
        assert!(!output.contains("private"));
        assert!(!output.contains("ABAB"));
    }
}
