//! Conversion from an owner-verified envelope to a release semantic handle.

use sha2::Digest as _;

use crate::{
    AuthorityError, CanonicalPayloadKind, Digest, InspectedCanonicalPayload, StageIssuerIdentity,
    VerifiedStagePayload,
};

/// Move-only release transition prepared from one owner-verified, reservation-bound envelope.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedStageTransition {
    stage: VerifiedStagePayload,
    admission: gocode_project_owner_authority::VerifiedStageAdmission,
    revalidated: bool,
}

impl VerifiedStageTransition {
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn command_fingerprint(&self) -> [u8; 32] {
        self.admission.command_fingerprint()
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn stage_kind(&self) -> CanonicalPayloadKind {
        self.stage.kind()
    }
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn inspected(&self) -> &InspectedCanonicalPayload {
        self.stage.inspected()
    }
    /// Recheck trusted freshness and revocation immediately before committing the transition.
    ///
    /// # Errors
    /// Returns the owner context's fail-closed result.
    pub fn revalidate(
        mut self,
        context: &dyn gocode_project_owner_authority::StageVerificationContext,
    ) -> Result<Self, AuthorityError> {
        self.admission
            .revalidate(context)
            .map_err(|_| AuthorityError::BindingMismatch)?;
        self.revalidated = true;
        Ok(self)
    }

    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedStagePayload,
        gocode_project_owner_authority::VerifiedStageAdmission,
        bool,
    ) {
        (self.stage, self.admission, self.revalidated)
    }
}

/// Consume an owner-verified envelope as the only production stage input.
///
/// # Errors
/// Returns an error when the embedded bytes, digest, or typed release contract diverges.
pub fn inspect_verified_stage_envelope(
    envelope: gocode_project_owner_authority::VerifiedStageEnvelope,
) -> Result<VerifiedStageTransition, AuthorityError> {
    let kind = match envelope.typed_payload().kind() {
        gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision => {
            CanonicalPayloadKind::Rc1Decision
        }
        gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization => {
            CanonicalPayloadKind::Rc2Authorization
        }
        gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization => {
            CanonicalPayloadKind::Rc3Authorization
        }
    };
    let exact = envelope.payload_bytes();
    let exact_sha256: [u8; 32] = sha2::Sha256::digest(exact).into();
    if exact_sha256 != envelope.payload_sha256() {
        return Err(AuthorityError::BindingMismatch);
    }
    let mut bytes = exact.to_vec();
    bytes.push(b'\n');
    let payload = InspectedCanonicalPayload::parse(kind, &bytes)?;
    let stage = VerifiedStagePayload {
        payload,
        envelope_payload_sha256: envelope.payload_sha256(),
        issuer: identity(envelope.issuer()),
        root: identity(envelope.root()),
        bootstrap: Digest::from_bytes(envelope.bootstrap_receipt_sha256()),
    };
    let admission = envelope
        .into_admission()
        .ok_or(AuthorityError::BindingMismatch)?;
    (admission
        .reservation()
        .map_err(|_| AuthorityError::BindingMismatch)?
        .kind()
        == match stage.kind() {
            CanonicalPayloadKind::Rc1Decision => {
                gocode_promotion_contracts::CanonicalPayloadKind::Rc1Decision
            }
            CanonicalPayloadKind::Rc2Authorization => {
                gocode_promotion_contracts::CanonicalPayloadKind::Rc2Authorization
            }
            CanonicalPayloadKind::Rc3Authorization => {
                gocode_promotion_contracts::CanonicalPayloadKind::Rc3Authorization
            }
            _ => return Err(AuthorityError::BindingMismatch),
        })
    .then_some(VerifiedStageTransition {
        stage,
        admission,
        revalidated: false,
    })
    .ok_or(AuthorityError::BindingMismatch)
}

fn identity(value: &gocode_project_owner_authority::VerifiedStageIssuer) -> StageIssuerIdentity {
    StageIssuerIdentity {
        principal: value.principal_id().into(),
        account: value.account_id().into(),
        lane: value.lane_id().into(),
        key: value.key_id().into(),
        signature_profile: value.signature_profile_id().into(),
    }
}
