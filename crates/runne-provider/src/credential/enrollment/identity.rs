use core::fmt;

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

    pub(crate) const fn bytes(self) -> [u8; 16] {
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

/// Opaque 256-bit ticket whose bytes may only enter the broker codec.
pub struct RawCredentialTicket([u8; 32]);

impl RawCredentialTicket {
    /// Accepts exactly one non-zero nonce produced by the platform OS CSPRNG.
    pub fn from_os_random(value: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Fails closed when the platform entropy source failed before issue.
    pub fn from_entropy<E>(value: Result<[u8; 32], E>) -> Result<Self, CredentialEnrollmentError> {
        Self::from_os_random(value.map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?)
    }

    pub(crate) const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
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
