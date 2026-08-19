//! Opaque scope binding a stage envelope to one store transition.

use crate::{CanonicalPayloadKind, ContractError};

/// Immutable scope minted by a promotion store before stage-envelope verification.
///
/// The constructor validates syntax only. A release store must additionally compare this scope
/// with its durable reservation before accepting the resulting verified transition.
#[derive(Debug, Eq, PartialEq)]
pub struct StageTransitionReservation {
    promotion: String,
    revision: u64,
    command: String,
    kind: CanonicalPayloadKind,
    fingerprint: [u8; 32],
}

impl StageTransitionReservation {
    /// Form a syntactically valid reservation scope for a store-owned transition.
    ///
    /// # Errors
    /// Returns an error when identifiers are outside the pinned canonical schema grammar.
    pub fn new(
        promotion: String,
        revision: u64,
        command: String,
        kind: CanonicalPayloadKind,
        fingerprint: [u8; 32],
    ) -> Result<Self, ContractError> {
        (crate::canonical_id(&promotion) && crate::canonical_id(&command) && revision < u64::MAX)
            .then_some(Self {
                promotion,
                revision,
                command,
                kind,
                fingerprint,
            })
            .ok_or(ContractError::InvalidCanonicalPayload)
    }

    /// Return the bound promotion identifier.
    #[must_use]
    pub fn promotion(&self) -> &str {
        &self.promotion
    }
    /// Return the exact expected revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Return the exact idempotency command.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }
    /// Return the stage kind permitted by this reservation.
    #[must_use]
    pub const fn kind(&self) -> CanonicalPayloadKind {
        self.kind
    }
    /// Return the store-derived scope fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
