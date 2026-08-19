use super::{ClaimWire, LedgerWire, SCHEMA, SlotWire};
use crate::rc2_effect_lease::ledger::{ClaimBinding, StoredRawEvidence};
use crate::{Digest, EffectLeaseError, FixtureRc2EffectLeaseLedger, Rc2SigningEffectLeaseState};

pub(crate) fn encode_ledger(
    ledger: &FixtureRc2EffectLeaseLedger,
) -> Result<Vec<u8>, EffectLeaseError> {
    let claims = ledger
        .bindings
        .iter()
        .map(|(namespace, binding)| ClaimWire {
            namespace: namespace.clone(),
            authority_instance: binding.authority_instance.to_hex(),
            promotion: binding.promotion.clone(),
            revision: binding.revision,
            authorization: binding.authorization.to_hex(),
            workflow: binding.workflow.to_hex(),
            signer: binding.signer.clone(),
            runner: binding.runner.clone(),
            slots: binding
                .slots
                .iter()
                .map(|(slot, digest, length)| SlotWire {
                    slot: slot.clone(),
                    digest: digest.to_hex(),
                    length: *length,
                })
                .collect(),
            generation: binding.generation,
            valid_from: binding.valid_from,
            expires_at: binding.expires_at,
            epoch: binding.epoch,
            states: ledger.states[namespace]
                .iter()
                .copied()
                .map(state)
                .map(str::to_owned)
                .collect(),
            reconciliations: ledger.reconciliations[namespace].to_vec(),
            consumed_commitment: ledger.consumed.get(namespace).map(|value| value.to_hex()),
            effect_evidence: evidence(ledger, namespace, true),
            native_evidence: evidence(ledger, namespace, false),
        })
        .collect();
    let mut bytes = serde_json::to_vec(&LedgerWire {
        schema_version: SCHEMA.into(),
        claims,
    })
    .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) fn decode_ledger(bytes: &[u8]) -> Result<FixtureRc2EffectLeaseLedger, EffectLeaseError> {
    let wire: LedgerWire =
        serde_json::from_slice(bytes).map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
    if wire.schema_version != SCHEMA {
        return Err(EffectLeaseError::DurableStateUnavailable);
    }
    let mut ledger = FixtureRc2EffectLeaseLedger::default();
    for claim in wire.claims {
        if claim.slots.len() != 3
            || claim.states.len() != 3
            || claim.reconciliations.len() != 3
            || ledger.bindings.contains_key(&claim.namespace)
        {
            return Err(EffectLeaseError::DurableStateUnavailable);
        }
        let slots: Vec<_> = claim
            .slots
            .into_iter()
            .map(|slot| Ok((slot.slot, digest(&slot.digest)?, slot.length)))
            .collect::<Result<_, EffectLeaseError>>()?;
        let states: Vec<_> = claim
            .states
            .into_iter()
            .map(|value| parse_state(&value))
            .collect::<Result<_, _>>()?;
        ledger.bindings.insert(
            claim.namespace.clone(),
            ClaimBinding {
                authority_instance: digest(&claim.authority_instance)?,
                promotion: claim.promotion,
                revision: claim.revision,
                authorization: digest(&claim.authorization)?,
                workflow: digest(&claim.workflow)?,
                signer: claim.signer,
                runner: claim.runner,
                slots: slots
                    .try_into()
                    .map_err(|_| EffectLeaseError::DurableStateUnavailable)?,
                generation: claim.generation,
                valid_from: claim.valid_from,
                expires_at: claim.expires_at,
                epoch: claim.epoch,
            },
        );
        ledger.states.insert(
            claim.namespace.clone(),
            states
                .try_into()
                .map_err(|_| EffectLeaseError::DurableStateUnavailable)?,
        );
        let namespace = claim.namespace;
        ledger.reconciliations.insert(
            namespace.clone(),
            claim
                .reconciliations
                .try_into()
                .map_err(|_| EffectLeaseError::DurableStateUnavailable)?,
        );
        if let Some(commitment) = claim.consumed_commitment {
            if !ledger.states[&namespace]
                .iter()
                .all(|state| *state == Rc2SigningEffectLeaseState::Completed)
            {
                return Err(EffectLeaseError::DurableStateUnavailable);
            }
            ledger
                .consumed
                .insert(namespace.clone(), digest(&commitment)?);
        }
        restore_evidence(
            &mut ledger.effect_evidence,
            &namespace,
            claim.effect_evidence,
        )?;
        restore_evidence(
            &mut ledger.native_evidence,
            &namespace,
            claim.native_evidence,
        )?;
    }
    encode_ledger(&ledger)
        .is_ok_and(|encoded| encoded == bytes)
        .then_some(ledger)
        .ok_or(EffectLeaseError::DurableStateUnavailable)
}

fn evidence(
    ledger: &FixtureRc2EffectLeaseLedger,
    namespace: &str,
    effect: bool,
) -> Vec<super::RawEvidenceWire> {
    let source = if effect {
        &ledger.effect_evidence
    } else {
        &ledger.native_evidence
    };
    source
        .iter()
        .filter(|((current, _), _)| current == namespace)
        .map(|((_, slot), evidence)| super::RawEvidenceWire {
            slot: slot.clone(),
            raw: crate::threshold_fixture_wire::hex(&evidence.raw),
            signature: crate::threshold_fixture_wire::hex(&evidence.signature),
        })
        .collect()
}

fn restore_evidence(
    target: &mut std::collections::BTreeMap<(String, String), StoredRawEvidence>,
    namespace: &str,
    evidence: Vec<super::RawEvidenceWire>,
) -> Result<(), EffectLeaseError> {
    for item in evidence {
        let signature = crate::store_durable_wire::bytes(&item.signature)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        let raw = crate::store_durable_wire::bytes(&item.raw)
            .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
        target.insert(
            (namespace.into(), item.slot),
            StoredRawEvidence {
                raw,
                signature: signature
                    .try_into()
                    .map_err(|_| EffectLeaseError::DurableStateUnavailable)?,
            },
        );
    }
    Ok(())
}

fn digest(value: &str) -> Result<Digest, EffectLeaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
    {
        return Err(EffectLeaseError::DurableStateUnavailable);
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| EffectLeaseError::DurableStateUnavailable)?,
            16,
        )
        .map_err(|_| EffectLeaseError::DurableStateUnavailable)?;
    }
    Ok(Digest::fixture(bytes))
}
const fn state(value: Rc2SigningEffectLeaseState) -> &'static str {
    match value {
        Rc2SigningEffectLeaseState::Planned => "planned",
        Rc2SigningEffectLeaseState::Claimed => "claimed",
        Rc2SigningEffectLeaseState::InFlight => "in_flight",
        Rc2SigningEffectLeaseState::Completed => "completed",
        Rc2SigningEffectLeaseState::Uncertain => "uncertain",
        Rc2SigningEffectLeaseState::Blocked => "blocked",
    }
}
fn parse_state(value: &str) -> Result<Rc2SigningEffectLeaseState, EffectLeaseError> {
    match value {
        "planned" => Ok(Rc2SigningEffectLeaseState::Planned),
        "claimed" => Ok(Rc2SigningEffectLeaseState::Claimed),
        "in_flight" => Ok(Rc2SigningEffectLeaseState::InFlight),
        "completed" => Ok(Rc2SigningEffectLeaseState::Completed),
        "uncertain" => Ok(Rc2SigningEffectLeaseState::Uncertain),
        "blocked" => Ok(Rc2SigningEffectLeaseState::Blocked),
        _ => Err(EffectLeaseError::DurableStateUnavailable),
    }
}
