//! Store-minted fixture publication capabilities.

use crate::{
    EffectError, EffectRequestFixture, InMemoryPromotionStore, PromotionId, PromotionState,
};

impl InMemoryPromotionStore {
    /// Mint an opaque effect capability only from this promotion's authorized RC3 record.
    ///
    /// # Errors
    /// Returns an error unless the exact promotion is currently publication-authorized.
    pub fn publication_authorized_binding(
        &self,
        id: &PromotionId,
    ) -> Result<crate::PublicationAuthorizedBinding, EffectError> {
        let record = self
            .entries
            .get(id)
            .ok_or(EffectError::AuthorizationBindingMismatch)?;
        if record.state != Some(PromotionState::PublicationAuthorized) {
            return Err(EffectError::MissingPublicationAuthorization);
        }
        let request =
            crate::PublicationEffectRequest::from_authorized_record(EffectRequestFixture {
                promotion: id.0.clone(),
                revision: record.revision,
                manifest: required(record.publication_manifest)?,
                destination: required_ref(record.publication_destination.as_ref())?.clone(),
                channel: required_ref(record.publication_channel.as_ref())?.clone(),
                executor: required_ref(record.publication_executor.as_ref())?.clone(),
                lane: required_ref(record.publication_lane.as_ref())?.clone(),
                workflow: required(record.publication_workflow)?,
                idempotency_namespace: required_ref(record.publication_namespace.as_ref())?.clone(),
                valid_from: required(record.publication_valid_from)?,
                expires_at: required(record.publication_expires_at)?,
                revocation_epoch: required(record.publication_revocation_epoch)?,
            })?;
        crate::PublicationAuthorizedBinding::from_authorized_record(
            request,
            required(record.publication_authorization)?,
        )
    }
}

fn required<T: Copy>(value: Option<T>) -> Result<T, EffectError> {
    value.ok_or(EffectError::AuthorizationBindingMismatch)
}

fn required_ref<T>(value: Option<&T>) -> Result<&T, EffectError> {
    value.ok_or(EffectError::AuthorizationBindingMismatch)
}
