//! Atomic durable admission for delegated stage envelopes.

use crate::AuthorityError;
use sha2::{Digest as _, Sha256};

/// Immutable authority scope for one signed stage-envelope admission.
///
/// The exact bootstrap, role, payload, nonce, and envelope digest close the
/// scope when the raw envelope format has no standalone promotion identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageAdmissionScope<'a> {
    /// Store-minted transition scope which must be checked before nonce admission.
    pub reservation: &'a runne_promotion_contracts::StageTransitionReservation,
    /// Verified V4 bootstrap digest.
    pub bootstrap_receipt_sha256: [u8; 32],
    /// Delegated stage role.
    pub role: &'a str,
    /// Canonical embedded payload digest, including its candidate binding.
    pub payload_sha256: [u8; 32],
    /// Signed authorization nonce.
    pub authorization_nonce: &'a str,
    /// Exact canonical outer-envelope digest.
    pub envelope_sha256: [u8; 32],
}

/// All values a durable backend must authenticate and observe atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageAdmissionRequest<'a> {
    /// Verified root-bootstrap validity window retained by the opaque V4 handle.
    pub bootstrap_validity: &'a crate::PromotionBootstrapValidity,
    /// Verified root identity, lineage, and revocation scope retained by V4.
    pub bootstrap_admission_scope: &'a crate::PromotionBootstrapAdmissionScope,
    /// Closed immutable stage scope.
    pub scope: StageAdmissionScope<'a>,
    /// Signed outer-envelope validity start.
    pub envelope_not_before: &'a str,
    /// Signed outer-envelope validity end.
    pub envelope_expires_at: &'a str,
    /// Signed outer-envelope revocation epoch.
    pub envelope_revocation_epoch: u64,
    /// Typed inner RC1/RC2/RC3 validity start in the backend's trusted stage clock.
    pub payload_valid_from: u64,
    /// Typed inner RC1/RC2/RC3 validity end in the backend's trusted stage clock.
    pub payload_expires_at: u64,
    /// Typed inner RC1/RC2/RC3 revocation epoch.
    pub payload_revocation_epoch: u64,
}

/// Owned facts for a provisionally admitted stage envelope.
///
/// This capability is intentionally not cloneable: it is moved with the verified envelope and
/// revalidated against the authenticated context immediately before store commitment.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStageAdmission {
    bootstrap_validity: crate::PromotionBootstrapValidity,
    bootstrap_scope: crate::PromotionBootstrapAdmissionScope,
    bootstrap_sha256: [u8; 32],
    role: String,
    payload_sha256: [u8; 32],
    nonce: String,
    envelope_sha256: [u8; 32],
    not_before: String,
    expires_at: String,
    envelope_epoch: u64,
    payload_valid_from: u64,
    payload_expires_at: u64,
    payload_epoch: u64,
    reservation: Option<runne_promotion_contracts::StageTransitionReservation>,
}

impl VerifiedStageAdmission {
    pub(crate) fn new(request: &StageAdmissionRequest<'_>) -> Self {
        Self {
            bootstrap_validity: request.bootstrap_validity.clone(),
            bootstrap_scope: request.bootstrap_admission_scope.clone(),
            bootstrap_sha256: request.scope.bootstrap_receipt_sha256,
            role: request.scope.role.into(),
            payload_sha256: request.scope.payload_sha256,
            nonce: request.scope.authorization_nonce.into(),
            envelope_sha256: request.scope.envelope_sha256,
            not_before: request.envelope_not_before.into(),
            expires_at: request.envelope_expires_at.into(),
            envelope_epoch: request.envelope_revocation_epoch,
            payload_valid_from: request.payload_valid_from,
            payload_expires_at: request.payload_expires_at,
            payload_epoch: request.payload_revocation_epoch,
            reservation: None,
        }
    }

    pub(crate) fn with_reservation(
        mut self,
        reservation: runne_promotion_contracts::StageTransitionReservation,
    ) -> Self {
        self.reservation = Some(reservation);
        self
    }

    /// Recheck current time and root/role revocation before a store transaction commits.
    ///
    /// # Errors
    /// Returns the authenticated context's fail-closed admission result.
    pub fn revalidate(
        &self,
        context: &dyn StageVerificationContext,
    ) -> Result<StageAdmission, AuthorityError> {
        context.admit_or_recover(&StageAdmissionRequest {
            bootstrap_validity: &self.bootstrap_validity,
            bootstrap_admission_scope: &self.bootstrap_scope,
            scope: StageAdmissionScope {
                reservation: self.reservation()?,
                bootstrap_receipt_sha256: self.bootstrap_sha256,
                role: &self.role,
                payload_sha256: self.payload_sha256,
                authorization_nonce: &self.nonce,
                envelope_sha256: self.envelope_sha256,
            },
            envelope_not_before: &self.not_before,
            envelope_expires_at: &self.expires_at,
            envelope_revocation_epoch: self.envelope_epoch,
            payload_valid_from: self.payload_valid_from,
            payload_expires_at: self.payload_expires_at,
            payload_revocation_epoch: self.payload_epoch,
        })
    }

    /// Return the store transition reservation carried by this admitted envelope.
    ///
    /// # Errors
    /// Returns a fail-closed error for legacy verification handles that were not transition-bound.
    pub fn reservation(
        &self,
    ) -> Result<&runne_promotion_contracts::StageTransitionReservation, AuthorityError> {
        self.reservation
            .as_ref()
            .ok_or(AuthorityError::InvalidStageEnvelope)
    }

    /// Return a framed immutable commitment for the exact store-bound stage admission.
    ///
    /// # Panics
    /// Panics only for a legacy admission that was not bound to a transition.
    #[must_use]
    pub fn command_fingerprint(&self) -> [u8; 32] {
        let reservation = self
            .reservation
            .as_ref()
            .expect("transition-bound admission");
        let fields: [&[u8]; 17] = [
            b"runne.release.stage-admission-command/1\0",
            &self.bootstrap_sha256,
            self.role.as_bytes(),
            &self.payload_sha256,
            self.nonce.as_bytes(),
            &self.envelope_sha256,
            self.bootstrap_validity.not_before().as_bytes(),
            self.bootstrap_validity.expires_at().as_bytes(),
            &self.bootstrap_scope.root_revocation_epoch().to_be_bytes(),
            self.not_before.as_bytes(),
            self.expires_at.as_bytes(),
            &self.envelope_epoch.to_be_bytes(),
            &self.payload_valid_from.to_be_bytes(),
            &self.payload_expires_at.to_be_bytes(),
            &self.payload_epoch.to_be_bytes(),
            reservation.promotion().as_bytes(),
            reservation.command().as_bytes(),
        ];
        let mut transcript = Vec::new();
        for field in fields {
            transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
            transcript.extend_from_slice(field);
        }
        transcript.extend_from_slice(&reservation.revision().to_be_bytes());
        transcript.extend_from_slice(&reservation.fingerprint());
        Sha256::digest(transcript).into()
    }
}

/// Outcome of one atomic durable stage admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageAdmission {
    /// The nonce was durably claimed for this exact authority scope.
    NewlyAdmitted,
    /// A previous crash left the same exact durable claim; recovery is allowed.
    ExistingSame,
}

/// Durable, externally supplied trust state required for stage verification.
///
/// Implementations authenticate one snapshot containing the UTC clock, the
/// stage-payload clock, the current root revocation generation, and the role's
/// revocation floor, then compare-and-set the complete [`StageAdmissionScope`]
/// together with the retained V4 root scope. `ExistingSame` is checked before
/// freshness expiry so a crash can recover, but it must still reject a changed
/// root or role revocation generation or any changed scope field. This crate
/// deliberately provides no default or trust-on-first-use backend.
pub trait StageVerificationContext {
    /// Atomically validate and durably admit, or recover, this exact request.
    ///
    /// A new admission must require both outer and typed payload freshness and
    /// non-revocation in the one authenticated snapshot, including current
    /// equality of the retained root revocation epoch. Recovery may bypass only
    /// freshness expiry after an exact prior admission; it must retain the same
    /// authenticated root and role revocation generations and immutable scope. A nonce
    /// collision with any differing scope must return
    /// [`AuthorityError::ReplayedStageEnvelope`].
    ///
    /// # Errors
    /// Returns a fail-closed error when the durable snapshot, revocation floor,
    /// or compare-and-set operation cannot be authenticated or completed.
    fn admit_or_recover(
        &self,
        request: &StageAdmissionRequest<'_>,
    ) -> Result<StageAdmission, AuthorityError>;
}
