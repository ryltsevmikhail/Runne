//! Opaque non-authorizing result for promotion-bootstrap `/4` prevalidation.

/// Cryptographically complete promotion-bootstrap `/4` validation result.
#[derive(Debug, Eq, PartialEq)]
pub struct PrevalidatedPromotionBootstrapV4 {
    pub(crate) receipt: crate::SignedPromotionBootstrapV4,
    pub(crate) root_public_key: [u8; 32],
    pub(crate) scope: crate::PromotionBootstrapAdmissionScope,
    pub(crate) validity: crate::PromotionBootstrapValidity,
    pub(crate) bindings: crate::PromotionBootstrapBindings,
}
