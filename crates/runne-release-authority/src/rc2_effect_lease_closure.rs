//! Move-only closure receipts for completed RC2 effect claims.

use sha2::{Digest as _, Sha256};

use super::ledger::{ClaimBinding, FixtureRc2EffectLeaseLedger};
use super::types::{
    EffectLeaseError, FixtureRc2EffectClosure, FixtureRc2SigningAuthorization,
    Rc2SigningEffectLeaseState,
};
use crate::Digest;

impl FixtureRc2EffectLeaseLedger {
    pub(crate) fn mint_completed_closure(
        &self,
        authorization: &FixtureRc2SigningAuthorization,
        commitment: Digest,
    ) -> Result<FixtureRc2EffectClosure, EffectLeaseError> {
        let binding = self
            .bindings
            .get(&authorization.0.namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        if !self.all_completed(authorization)
            || self.consumed.contains_key(&authorization.0.namespace)
        {
            return Err(EffectLeaseError::InvalidLeaseState);
        }
        Ok(FixtureRc2EffectClosure {
            authority_instance: binding.authority_instance,
            promotion: binding.promotion.clone(),
            namespace: authorization.0.namespace.clone(),
            generation: binding.generation,
            authorization: binding.authorization,
            commitment,
            ledger_identity: identity(binding),
        })
    }

    pub(crate) fn consume_completed_closure(
        &mut self,
        closure: FixtureRc2EffectClosure,
    ) -> Result<(), EffectLeaseError> {
        let binding = self
            .bindings
            .get(&closure.namespace)
            .ok_or(EffectLeaseError::InvalidLeaseState)?;
        if binding.authority_instance != closure.authority_instance
            || binding.promotion != closure.promotion
            || binding.authorization != closure.authorization
            || binding.generation != closure.generation
            || identity(binding) != closure.ledger_identity
            || !self.states[&closure.namespace]
                .iter()
                .all(|state| *state == Rc2SigningEffectLeaseState::Completed)
            || self.consumed.contains_key(&closure.namespace)
        {
            return Err(EffectLeaseError::InvalidLeaseState);
        }
        self.consumed.insert(closure.namespace, closure.commitment);
        Ok(())
    }
}

fn identity(binding: &ClaimBinding) -> Digest {
    let mut bytes = b"runne.release.rc2-effect-ledger-claim/1\0".to_vec();
    for value in [
        binding.authority_instance.as_bytes().as_slice(),
        binding.promotion.as_bytes(),
        binding.signer.as_bytes(),
        binding.runner.as_bytes(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    for digest in [binding.authorization, binding.workflow] {
        bytes.extend_from_slice(&digest.as_bytes());
    }
    for (slot, digest, length) in &binding.slots {
        bytes.extend_from_slice(&(slot.len() as u64).to_be_bytes());
        bytes.extend_from_slice(slot.as_bytes());
        bytes.extend_from_slice(&digest.as_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
    }
    for value in [
        binding.revision,
        binding.generation,
        binding.valid_from,
        binding.expires_at,
        binding.epoch,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Digest::from_bytes(Sha256::digest(bytes).into())
}
