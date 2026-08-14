//! Global durable threshold acknowledgement and snapshot operations.
#![allow(clippy::missing_errors_doc)] // Fixture durable transaction forwarding.

use crate::{
    AuthorityError, CommandId, DurableFixturePromotionAuthority, PromotionId, TransactionOutcome,
};

impl DurableFixturePromotionAuthority {
    pub fn snapshot(
        &self,
        id: &PromotionId,
    ) -> Result<crate::PromotionStateSnapshot, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        self.load()?
            .entries
            .get(id)
            .and_then(|record| record.snapshot.clone())
            .ok_or(AuthorityError::InvalidTransition)
    }
    pub fn acknowledge_threshold_completion(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        context: &dyn crate::ThresholdVerificationContext,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let record = store
            .entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?;
        if let Some(tombstone) = &record.threshold_ack {
            let fingerprint = crate::store_command::threshold_ack_fingerprint(
                id,
                expected,
                &command,
                tombstone.admission,
            );
            return (tombstone.claim_revision == expected
                && tombstone.command == command.as_str()
                && tombstone.fingerprint == fingerprint)
                .then(|| tombstone.outcome.clone())
                .ok_or(AuthorityError::CommandReplayDiverged);
        }
        let (claim, fingerprint) =
            crate::store_transition::begin_ack(record, id, expected, &command)?;
        self.save(&store)?;
        let proof =
            context.acknowledge_or_recover(&crate::ThresholdAckRequest { claim: &claim })?;
        let record = store
            .entries
            .get_mut(id)
            .ok_or(AuthorityError::InvalidTransition)?;
        let outcome =
            crate::store_transition::settle_ack(record, id, command, claim, proof, fingerprint)?;
        self.save(&store)?;
        Ok(outcome)
    }
}
