use core::fmt;

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::CredentialEnrollmentError;

macro_rules! non_zero_u64 {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Constructs a non-zero monotonic value.
            pub fn new(value: u64) -> Result<Self, CredentialEnrollmentError> {
                if value == 0 {
                    return Err(CredentialEnrollmentError::InvalidInput);
                }
                Ok(Self(value))
            }

            /// Returns the exact monotonic value.
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

/// Exact 128-bit durable enrollment operation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialOperationId([u8; 16]);

impl CredentialOperationId {
    /// Validates a non-zero, exactly 16-byte operation identity.
    pub fn from_bytes(value: [u8; 16]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 16] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the fixed-width safe durable operation identity.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

non_zero_u64!(
    CredentialLifecycleRevision,
    "Non-zero authoritative lifecycle revision."
);
non_zero_u64!(CredentialFence, "Non-zero provider dispatch fence.");
non_zero_u64!(CredentialTicketAttempt, "Non-zero one-shot ticket attempt.");

/// A fixed-width digest obtained from an independently measured input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialBindingDigest([u8; 32]);

impl CredentialBindingDigest {
    /// Validates a non-zero, exactly 32-byte measured digest.
    pub fn from_measured(value: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the fixed-width measured digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

const TICKET_DIGEST_DOMAIN: &[u8] = b"GOCODE_CREDENTIAL_TICKET_V2\0";

/// Opaque 256-bit OS-CSPRNG ticket whose bytes may only enter the broker codec.
pub struct RawCredentialTicket([u8; 32]);

impl RawCredentialTicket {
    /// Generates a fresh 256-bit nonce directly from the operating-system CSPRNG.
    pub fn generate() -> Result<Self, CredentialEnrollmentError> {
        generate_ticket_with(|bytes| rand::rngs::OsRng.try_fill_bytes(bytes).map_err(|_| ()))
    }

    /// Returns the durable domain-separated digest; raw bytes remain opaque.
    pub fn binding_digest(&self) -> CredentialBindingDigest {
        let mut hasher = Sha256::new();
        hasher.update(TICKET_DIGEST_DOMAIN);
        hasher.update((self.0.len() as u64).to_be_bytes());
        hasher.update(self.0);
        CredentialBindingDigest::from_measured(hasher.finalize().into())
            .expect("SHA-256 is non-zero")
    }

    pub(crate) const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[allow(dead_code)]
    pub(super) fn from_decoded(value: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(Self(value))
    }
}

fn generate_ticket_with(
    fill: impl FnOnce(&mut [u8; 32]) -> Result<(), ()>,
) -> Result<RawCredentialTicket, CredentialEnrollmentError> {
    let mut bytes = [0_u8; 32];
    fill(&mut bytes).map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
    if bytes == [0; 32] {
        bytes.zeroize();
        return Err(CredentialEnrollmentError::EntropyUnavailable);
    }
    Ok(RawCredentialTicket(bytes))
}

impl Drop for RawCredentialTicket {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for RawCredentialTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawCredentialTicket(<redacted>)")
    }
}

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
