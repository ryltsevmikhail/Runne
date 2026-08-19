//! Canonical root-wire persistence and lock-coupled monotonic anchoring.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

use crate::store_durable_lease::AuthorityAnchor;
use crate::{AuthorityError, Digest, InMemoryPromotionStore};

use super::DurableFixturePromotionAuthority;
use super::authority_wire::{self, AuthorityWire};

impl DurableFixturePromotionAuthority {
    pub(super) fn create(&self, source: &InMemoryPromotionStore) -> Result<(), AuthorityError> {
        self.validate_store_identity(source)?;
        let bytes = self.encode_at(source, 1, None)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)?;
        crate::store_durable_file::sync_parent(&self.path)?;
        self.lease
            .initialize_authority_anchor(anchor(self.authority_instance, 1, &bytes))
    }

    pub(crate) fn load(&self) -> Result<InMemoryPromotionStore, AuthorityError> {
        if self.poisoned.get() {
            return Err(AuthorityError::DurableStateUnavailable);
        }
        let (wire, bytes) = self.read_wire()?;
        let (current, repair) = self.anchor_status(&wire, &bytes)?;
        let store = self.restore(&wire)?;
        if let Some(expected) = repair {
            self.lease.update_authority_anchor(expected, current)?;
        }
        Ok(store)
    }

    pub(crate) fn save(&self, store: &InMemoryPromotionStore) -> Result<(), AuthorityError> {
        if self.poisoned.get() {
            return Err(AuthorityError::DurableStateUnavailable);
        }
        self.validate_store_identity(store)?;
        let (current, bytes) = self.read_wire()?;
        let (expected, repair) = self.anchor_status(&current, &bytes)?;
        if let Some(previous) = repair {
            self.restore(&current)?;
            self.lease.update_authority_anchor(previous, expected)?;
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::DurableStateUnavailable)?;
        let next = self.encode_at(store, generation, Some(expected.authority_file.to_hex()))?;
        crate::store_durable_file::safe_file(&self.path)?;
        let temp = crate::store_durable_file::temp_file(&self.path, &next)?;
        if fs::rename(temp, &self.path).is_err() {
            return Err(AuthorityError::DurableStateUnavailable);
        }
        #[cfg(all(test, feature = "fixture-only"))]
        if self.take_publication_failpoint(
            crate::publication_effect_failpoint::PublicationEffectFailpoint::AfterRenameBeforeParentSync,
        ) {
            self.poisoned.set(true);
            return Err(AuthorityError::DurableStateUnavailable);
        }
        let committed = (|| {
            crate::store_durable_file::safe_file(&self.path)?;
            crate::store_durable_file::sync_parent(&self.path)?;
            self.lease.update_authority_anchor(
                expected,
                anchor(self.authority_instance, generation, &next),
            )
        })();
        if committed.is_err() {
            self.poisoned.set(true);
        }
        committed
    }

    fn read_wire(&self) -> Result<(AuthorityWire, Vec<u8>), AuthorityError> {
        crate::store_durable_file::safe_file(&self.path)?;
        let mut bytes = Vec::new();
        File::open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        let wire: AuthorityWire =
            serde_json::from_slice(&bytes).map_err(|_| AuthorityError::NonCanonicalPayload)?;
        if authority_wire::encode(&wire)? != bytes
            || wire.schema_version != "runne.release.durable-promotion-authority/1"
            || wire.bootstrap != self.binding.bootstrap.to_hex()
            || wire.profile != self.binding.profile
            || wire.version != self.binding.version
            || wire.promotions.is_empty()
        {
            return Err(AuthorityError::NonCanonicalPayload);
        }
        Ok((wire, bytes))
    }

    fn anchor_status(
        &self,
        wire: &AuthorityWire,
        bytes: &[u8],
    ) -> Result<(AuthorityAnchor, Option<AuthorityAnchor>), AuthorityError> {
        let authority_instance = wire_authority(wire)?;
        let current = anchor(authority_instance, wire.generation, bytes);
        let expected = self.lease.authority_anchor()?;
        if current == expected {
            return Ok((current, None));
        }
        if current.authority_instance == expected.authority_instance
            && current.generation == expected.generation.checked_add(1).unwrap_or(0)
            && wire.previous_authority_sha256 == Some(expected.authority_file.to_hex())
        {
            return Ok((current, Some(expected)));
        }
        Err(AuthorityError::DurableStateUnavailable)
    }

    fn restore(&self, wire: &AuthorityWire) -> Result<InMemoryPromotionStore, AuthorityError> {
        if self.authority_instance != Digest::from_bytes([0; 32])
            && wire_authority(wire)? != self.authority_instance
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let mut entries = BTreeMap::new();
        let mut stage_claims = BTreeMap::new();
        for state in &wire.promotions {
            let (id, record) = crate::store_durable_wire::into_record(state, &self.binding)?;
            if entries.insert(id, record).is_some() {
                return Err(AuthorityError::NonCanonicalPayload);
            }
        }
        for record in entries.values() {
            for claim in record.stage_claims.values() {
                if let Some(existing) = stage_claims.insert(claim.nonce.clone(), claim.clone())
                    && existing != *claim
                {
                    return Err(AuthorityError::NonCanonicalPayload);
                }
            }
        }
        let authority_instance = wire_authority(wire)?;
        if entries
            .values()
            .any(|record| record.authority_instance != authority_instance)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        let publication_effect_ledger = crate::publication_effect_durable::decode_ledger(
            &crate::store_durable_wire::bytes(&wire.publication_effect_ledger)?,
        )
        .map_err(|_| AuthorityError::NonCanonicalPayload)?;
        crate::store_durable_publication_binding::validate(
            authority_instance,
            &entries,
            &publication_effect_ledger,
        )?;
        Ok(InMemoryPromotionStore {
            authority_instance,
            entries,
            stage_claims,
            rc2_effect_ledger: crate::rc2_effect_lease::decode_ledger(
                &crate::store_durable_wire::bytes(&wire.effect_ledger)?,
            )
            .map_err(|_| AuthorityError::NonCanonicalPayload)?,
            publication_effect_ledger,
        })
    }

    fn encode_at(
        &self,
        store: &InMemoryPromotionStore,
        generation: u64,
        previous_authority_sha256: Option<String>,
    ) -> Result<Vec<u8>, AuthorityError> {
        let promotions = store
            .entries
            .iter()
            .map(|(id, record)| crate::store_durable_wire::from_record(&self.binding, id, record))
            .collect::<Result<Vec<_>, _>>()?;
        authority_wire::encode(&authority_wire::seal(AuthorityWire {
            schema_version: "runne.release.durable-promotion-authority/1".into(),
            bootstrap: self.binding.bootstrap.to_hex(),
            profile: self.binding.profile.clone(),
            version: self.binding.version,
            authority_instance: self.authority_instance.to_hex(),
            generation,
            previous_authority_sha256,
            promotions,
            effect_ledger: crate::threshold_fixture_wire::hex(
                &crate::rc2_effect_lease::encode_ledger(&store.rc2_effect_ledger)
                    .map_err(|_| AuthorityError::DurableStateUnavailable)?,
            ),
            publication_effect_ledger: crate::threshold_fixture_wire::hex(
                &crate::publication_effect_durable::encode_ledger(&store.publication_effect_ledger)
                    .map_err(|_| AuthorityError::DurableStateUnavailable)?,
            ),
            publication_effect_ledger_sha256: String::new(),
            publication_effect_outer_sha256: String::new(),
        })?)
    }

    fn validate_store_identity(
        &self,
        store: &InMemoryPromotionStore,
    ) -> Result<(), AuthorityError> {
        if store.authority_instance != self.authority_instance
            || store
                .entries
                .values()
                .any(|record| record.authority_instance != self.authority_instance)
        {
            return Err(AuthorityError::BindingMismatch);
        }
        crate::store_durable_publication_binding::validate(
            self.authority_instance,
            &store.entries,
            &store.publication_effect_ledger,
        )
    }
}

fn wire_authority(wire: &AuthorityWire) -> Result<Digest, AuthorityError> {
    crate::store_durable_wire::bytes(&wire.authority_instance)?
        .try_into()
        .map(Digest::from_bytes)
        .map_err(|_| AuthorityError::NonCanonicalPayload)
}

fn anchor(authority_instance: Digest, generation: u64, bytes: &[u8]) -> AuthorityAnchor {
    AuthorityAnchor {
        authority_instance,
        generation,
        authority_file: authority_wire::file_digest(bytes),
    }
}
