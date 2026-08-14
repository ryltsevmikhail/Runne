/// Immutable five-dimensional issuer identity extracted during stage-envelope verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStageIssuer {
    pub(crate) principal: String,
    pub(crate) account: String,
    pub(crate) lane: String,
    pub(crate) key: String,
    pub(crate) signature_profile: String,
}
impl VerifiedStageIssuer {
    /// Return the verified immutable principal identifier.
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal
    }
    /// Return the verified controlling-account identifier.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account
    }
    /// Return the verified protected-lane identifier.
    #[must_use]
    pub fn lane_id(&self) -> &str {
        &self.lane
    }
    /// Return the verified signing-key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key
    }
    /// Return the verified signature-profile identifier.
    #[must_use]
    pub fn signature_profile_id(&self) -> &str {
        &self.signature_profile
    }
}
