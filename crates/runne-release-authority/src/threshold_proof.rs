//! Move-only proof minting after an exact threshold admission outcome.

use sha2::{Digest as _, Sha256};

use crate::{
    AuthorityError, Digest, ThresholdAdmission, ThresholdAdmissionRequest,
    ThresholdVerificationContext,
};

/// Move-only proof minted only from exact receipt, bundle and atomic backend outcome.
#[derive(Debug, Eq, PartialEq)]
pub struct DurableThresholdProof {
    authority_instance: Digest,
    promotion: crate::PromotionId,
    revision: u64,
    authorization: Digest,
    candidate: Digest,
    inventory: Digest,
    metadata: Digest,
    report: Digest,
    commitment: Digest,
    command: String,
    admission: Digest,
}
impl DurableThresholdProof {
    pub(crate) fn command_scope(&self) -> Digest {
        let mut transcript = b"runne.release.verify-signed-operation-scope/1\0".to_vec();
        for field in [self.promotion.0.as_bytes(), self.command.as_bytes()] {
            append(&mut transcript, field);
        }
        append(&mut transcript, &self.authority_instance.as_bytes());
        append(&mut transcript, &self.revision.to_be_bytes());
        for digest in [
            self.authorization,
            self.candidate,
            self.inventory,
            self.metadata,
            self.report,
            self.commitment,
            self.admission,
        ] {
            append(&mut transcript, &digest.as_bytes());
        }
        Digest::from_bytes(Sha256::digest(transcript).into())
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::PromotionId,
        u64,
        Digest,
        Digest,
        Digest,
        Digest,
        Digest,
        Digest,
        Digest,
    ) {
        (
            self.promotion,
            self.revision,
            self.authorization,
            self.candidate,
            self.inventory,
            self.metadata,
            self.report,
            self.commitment,
            self.admission,
        )
    }
    pub(crate) const fn authority_instance(&self) -> Digest {
        self.authority_instance
    }
    pub(crate) fn matches_command(&self, command: &crate::CommandId) -> bool {
        self.command == command.as_str()
    }
}

/// Obtain a move-only proof after the store has durably reserved the exact prevalidated bundle.
///
/// # Errors
/// Returns an error unless the receipt, bundle, and atomic backend outcome are exact.
#[allow(clippy::needless_pass_by_value)] // Consumes unforgeable receipt and bundle capabilities.
pub fn admit_prevalidated_signed_bundle(
    bundle: crate::FixturePrevalidatedSignedBundle,
    receipt: crate::SigningAuthorizedReceipt,
    context: &dyn ThresholdVerificationContext,
) -> Result<DurableThresholdProof, AuthorityError> {
    if bundle.authority_instance() != receipt.authority_instance()
        || bundle.authorization() != receipt.authorization()
        || bundle.commitment() != receipt.commitment()
    {
        return Err(AuthorityError::BindingMismatch);
    }
    let request = ThresholdAdmissionRequest {
        evidence: bundle.evidence(),
        bundle: &bundle,
        receipt: &receipt,
    };
    let admission = match context.recover_existing(&request)? {
        Some(
            ThresholdAdmission::NewlyAdmitted { admission_id }
            | ThresholdAdmission::ExistingSame { admission_id },
        ) => admission_id,
        None => {
            let (state, now) = context.trusted_state_and_now()?;
            match context.persist_new(request.validate_new(&state, now)?)? {
                ThresholdAdmission::NewlyAdmitted { admission_id }
                | ThresholdAdmission::ExistingSame { admission_id } => admission_id,
            }
        }
    };
    Ok(DurableThresholdProof {
        authority_instance: receipt.authority_instance(),
        promotion: receipt.promotion().clone(),
        revision: receipt.revision(),
        authorization: receipt.authorization(),
        candidate: bundle.candidate(),
        inventory: bundle.inventory(),
        metadata: bundle.metadata(),
        report: bundle.report(),
        commitment: bundle.commitment(),
        command: receipt.command().into(),
        admission,
    })
}

fn append(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
    transcript.extend_from_slice(field);
}
