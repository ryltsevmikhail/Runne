//! Store-internal recovery leases for non-dispatch response-loss transitions.

use crate::publication_effect_ledger::{FixturePublicationEffectLedger, live_capability};
use crate::publication_effect_types::{
    FixturePublicationDispatch, PublicationDispatchLease, PublicationEffectError,
    PublicationEffectScope, PublicationEffectState,
};

impl FixturePublicationEffectLedger {
    pub(crate) fn response_loss_capability(
        &self,
        namespace: &str,
        expected: PublicationEffectState,
    ) -> Result<FixturePublicationDispatch, PublicationEffectError> {
        let binding = self
            .bindings
            .get(namespace)
            .filter(|binding| binding.state == expected)
            .ok_or(PublicationEffectError::InvalidState)?;
        Ok(FixturePublicationDispatch(PublicationDispatchLease {
            authority_instance: binding.scope.authority_instance,
            idempotency_namespace: namespace.into(),
            generation: binding.scope.generation,
            capability: live_capability(binding),
        }))
    }

    pub(crate) fn scope_for_namespace(
        &self,
        namespace: &str,
    ) -> Result<&PublicationEffectScope, PublicationEffectError> {
        self.bindings
            .get(namespace)
            .map(|binding| &binding.scope)
            .ok_or(PublicationEffectError::InvalidState)
    }
}
