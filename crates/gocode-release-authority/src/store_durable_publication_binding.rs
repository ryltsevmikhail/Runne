//! Relational validation between embedded effect scopes and outer promotion records.

use std::collections::BTreeMap;

use crate::publication_effect_ledger::FixturePublicationEffectLedger;
use crate::{AuthorityError, Digest, PromotionId, PromotionState};

pub fn validate(
    authority_instance: Digest,
    entries: &BTreeMap<PromotionId, crate::store_machine::Record>,
    ledger: &FixturePublicationEffectLedger,
) -> Result<(), AuthorityError> {
    for binding in ledger.bindings.values() {
        let scope = &binding.scope;
        let record = entries
            .get(&PromotionId::try_fixture(&scope.promotion)?)
            .ok_or(AuthorityError::BindingMismatch)?;
        let exact = scope.authority_instance == authority_instance
            && record.authority_instance == authority_instance
            && record.state == Some(PromotionState::PublicationAuthorized)
            && record
                .binding
                .is_some_and(|candidate| candidate.candidate() == scope.candidate_digest)
            && record.publication_authorization == Some(scope.rc3_authorization_digest)
            && record.publication_manifest == Some(scope.manifest_digest)
            && record.publication_destination.as_deref() == Some(scope.destination.as_str())
            && record.publication_channel.as_deref() == Some(scope.channel.as_str())
            && record.publication_namespace.as_deref()
                == Some(scope.idempotency_namespace.as_str())
            && record.publication_workflow == Some(scope.workflow_digest)
            && record.publication_valid_from == Some(scope.valid_from)
            && record.publication_expires_at == Some(scope.expires_at)
            && record.publication_revocation_epoch == Some(scope.revocation_epoch);
        if !exact {
            return Err(AuthorityError::BindingMismatch);
        }
    }
    Ok(())
}
