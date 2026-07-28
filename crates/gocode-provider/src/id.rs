use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum byte length of provider/model/revision identifiers.
pub const MAX_PROVIDER_ID_BYTES: usize = 128;

/// A rejected bounded provider identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidProviderId {
    /// The identifier was empty.
    #[error("provider identifier is empty")]
    Empty,
    /// The identifier exceeded the byte limit.
    #[error("provider identifier is too long: max={max}, actual={actual}")]
    TooLong {
        /// Maximum accepted bytes.
        max: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// The identifier contained a control or non-ASCII character.
    #[error("provider identifier contains an invalid character")]
    InvalidCharacter,
}

/// Stable bounded provider identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderId(String);

impl ProviderId {
    /// Constructs a bounded printable ASCII provider identity.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidProviderId> {
        bounded_identifier(value.into()).map(Self)
    }

    /// Returns the identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub(crate) fn bounded_identifier(value: String) -> Result<String, InvalidProviderId> {
    if value.is_empty() {
        return Err(InvalidProviderId::Empty);
    }
    if value.len() > MAX_PROVIDER_ID_BYTES {
        return Err(InvalidProviderId::TooLong {
            max: MAX_PROVIDER_ID_BYTES,
            actual: value.len(),
        });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(InvalidProviderId::InvalidCharacter);
    }
    Ok(value)
}

/// Durable identity of one normalized provider call.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderCallId([u8; 16]);

impl ProviderCallId {
    /// Constructs an identity from validated bytes owned by the caller.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ProviderCallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderCallId")
            .field(&self.0)
            .finish()
    }
}

macro_rules! provider_binary_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Constructs an identity from validated bytes owned by the caller.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Returns the raw identity bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

provider_binary_id!(
    DispatchAttemptId,
    "Durable identity of one provider dispatch attempt."
);
provider_binary_id!(
    ProviderStreamId,
    "Transient identity of one normalized provider stream."
);
