//! Opaque receipt accessors restricted to fixture store internals.

use crate::{Digest, PromotionId};

/// Opaque fixture authorization proof minted only from an exact store reservation.
#[derive(Debug, Eq, PartialEq)]
pub struct SigningAuthorizedReceipt {
    pub(crate) authority_instance: Digest,
    pub(crate) promotion: PromotionId,
    pub(crate) revision: u64,
    pub(crate) authorization: Digest,
    pub(crate) command: String,
    pub(crate) commitment: Digest,
}
impl SigningAuthorizedReceipt {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) const fn authority_instance(&self) -> Digest {
        self.authority_instance
    }
    pub(crate) const fn authorization(&self) -> Digest {
        self.authorization
    }
    pub(crate) const fn commitment(&self) -> Digest {
        self.commitment
    }
    pub(crate) fn command(&self) -> &str {
        &self.command
    }
    pub(crate) const fn promotion(&self) -> &PromotionId {
        &self.promotion
    }
}
