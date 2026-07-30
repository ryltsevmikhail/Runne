//! Типы домена безопасности: principal, grant identity и канонические цели.
//! Чистый доменный код: без async, IO и внешних зависимостей.

use core::fmt;

use crate::id::{InvalidIdReason, SecretRefId, uuid_v7_newtype};
use crate::timestamp::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrincipalIdentity {
    Embedded {
        host_id: String,
        attested_at: Timestamp,
    },
    Daemon {
        token_id: String,
        session_id: String,
        issued_at: Timestamp,
        expires_at: Timestamp,
    },
    System {
        purpose: SystemPurpose,
        capability_ref: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemPurpose {
    Cleanup,
    Recovery,
    Admin,
}

impl PrincipalIdentity {
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        match self {
            Self::Daemon { expires_at, .. } => *expires_at < now,
            _ => false,
        }
    }
}

uuid_v7_newtype!(GrantId, "Идентификатор CapabilityGrant — UUIDv7.");

/// Opaque, non-authorizing reference to a registered secret.
///
/// The reference deliberately contains neither secret material nor metadata
/// that could reveal its provider, label, or value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    /// Fresh UUIDv7 identity allocated by the secret broker.
    pub secret_ref_id: SecretRefId,
    /// Positive version of the secret material.
    pub version: u64,
}

impl SecretRef {
    /// Creates an opaque secret reference with a positive version.
    pub fn new(secret_ref_id: SecretRefId, version: u64) -> Result<Self, SecretRefError> {
        if version == 0 {
            return Err(SecretRefError::ZeroVersion);
        }
        Ok(Self {
            secret_ref_id,
            version,
        })
    }
}

/// Reason an opaque secret reference was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRefError {
    /// Secret versions start at one.
    ZeroVersion,
}

impl fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroVersion => write!(f, "secret reference version must be positive"),
        }
    }
}

impl std::error::Error for SecretRefError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthEpoch(u64);

impl AuthEpoch {
    pub const INITIAL: Self = Self(1);

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AuthEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const INITIAL: Self = Self(1);

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalAction(String);

impl CanonicalAction {
    pub fn new(s: &str) -> Result<Self, InvalidActionReason> {
        if s.is_empty() {
            return Err(InvalidActionReason::Empty);
        }
        if s.len() > 128 {
            return Err(InvalidActionReason::TooLong {
                max: 128,
                actual: s.len(),
            });
        }
        if s.contains(|c: char| c.is_control()) {
            return Err(InvalidActionReason::ControlCharacters);
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidActionReason {
    Empty,
    TooLong { max: usize, actual: usize },
    ControlCharacters,
}

impl fmt::Display for InvalidActionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "action is empty"),
            Self::TooLong { max, actual } => write!(f, "action too long: {actual} > {max}"),
            Self::ControlCharacters => write!(f, "action contains control characters"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedResource(String);

impl NormalizedResource {
    pub fn new(s: &str) -> Result<Self, InvalidResourceReason> {
        if s.is_empty() {
            return Err(InvalidResourceReason::Empty);
        }
        if s.len() > 512 {
            return Err(InvalidResourceReason::TooLong {
                max: 512,
                actual: s.len(),
            });
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidResourceReason {
    Empty,
    TooLong { max: usize, actual: usize },
}

impl fmt::Display for InvalidResourceReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "resource is empty"),
            Self::TooLong { max, actual } => write!(f, "resource too long: {actual} > {max}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: String,
    pub principal: PrincipalIdentity,
    pub auth_epoch: AuthEpoch,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

impl SessionBinding {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at < now || self.principal.is_expired(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn canonical_action_rejects_empty() {
        assert!(CanonicalAction::new("").is_err());
    }
    #[test]
    fn canonical_action_rejects_control_chars() {
        assert!(CanonicalAction::new("read\nfile").is_err());
    }
    #[test]
    fn canonical_action_accepts_valid() {
        assert_eq!(CanonicalAction::new("fs:read").unwrap().as_str(), "fs:read");
    }
    #[test]
    fn normalized_resource_accepts_valid() {
        assert_eq!(
            NormalizedResource::new("workspace:/src/main.rs")
                .unwrap()
                .as_str(),
            "workspace:/src/main.rs"
        );
    }
    #[test]
    fn auth_epoch_is_monotonic() {
        assert!(AuthEpoch::INITIAL.next() > AuthEpoch::INITIAL);
    }
    #[test]
    fn generation_is_monotonic() {
        assert!(Generation::INITIAL.next() > Generation::INITIAL);
    }
    #[test]
    fn system_principal_is_system() {
        assert!(
            PrincipalIdentity::System {
                purpose: SystemPurpose::Cleanup,
                capability_ref: "cleanup".into()
            }
            .is_system()
        );
    }
    #[test]
    fn daemon_expires() {
        let principal = PrincipalIdentity::Daemon {
            token_id: "t1".into(),
            session_id: "s1".into(),
            issued_at: Timestamp::from_unix_micros(0),
            expires_at: Timestamp::from_unix_micros(500),
        };
        assert!(principal.is_expired(Timestamp::from_unix_micros(1000)));
    }
    #[test]
    fn grant_id_display_roundtrip() {
        let id = GrantId::from_bytes([0, 1, 2, 3, 4, 5, 0x70, 7, 0x80, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(id, GrantId::from_str(&id.to_string()).unwrap());
    }
}
