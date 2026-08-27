use std::fmt;

use hmac::{Hmac, Mac};
use runne_application::provider::ProviderJournalKeyBinding;
use runne_secure_store::{
    ProviderJournalKeyMaterial, ProviderJournalKeyRef, ProviderJournalKeyring,
};
use rusqlite::Connection;
use sha2::Sha256;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use super::ProviderAdmissionError;
use rusqlite::OptionalExtension;

mod fields;

pub(crate) use fields::{CommittedEffectProofFields, IssuanceProofFields};

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod tests;

const ISSUANCE_DOMAIN: &[u8] = b"runne/provider-online-issuance-proof/v1";
const EFFECT_DOMAIN: &[u8] = b"runne/provider-online-effect-proof/v1";

pub(crate) struct OnlineEffectProofState(Mutex<Option<OnlineEffectProofCapabilitySet>>);

impl OnlineEffectProofState {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(None))
    }

    pub(crate) fn lock(
        &self,
    ) -> Result<MutexGuard<'_, Option<OnlineEffectProofCapabilitySet>>, ProviderAdmissionError>
    {
        self.0
            .lock()
            .map_err(|_| ProviderAdmissionError::AuthorityDenied)
    }

    #[cfg(test)]
    pub(crate) fn get(&self) -> Option<()> {
        self.0.lock().ok()?.as_ref().map(|_| ())
    }
}

pub(crate) struct OnlineEffectProofCapabilitySet {
    active: ProofKey,
    retained: Vec<ProofKey>,
}

struct ProofKey {
    binding: ProviderJournalKeyBinding,
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for OnlineEffectProofCapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnlineEffectProofCapabilitySet")
            .field("active_binding", &self.active.binding)
            .field("retained_key_count", &self.retained.len())
            .finish()
    }
}

impl OnlineEffectProofCapabilitySet {
    pub(crate) fn load(
        connection: &Connection,
        keyring: &dyn ProviderJournalKeyring,
        active_binding: ProviderJournalKeyBinding,
    ) -> Result<Self, ProviderAdmissionError> {
        let active = load_key(keyring, active_binding)?;
        let mut statement = connection.prepare(
            "SELECT DISTINCT journal_key_id, journal_key_version, journal_runtime_authority_id, \
             journal_database_generation FROM provider_online_dispatch_issuance_evidence \
             ORDER BY journal_key_id, journal_key_version, journal_runtime_authority_id, \
             journal_database_generation",
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let bindings = statement
            .query_map([], |row| {
                Ok((
                    decode_array(row.get(0)?)?,
                    u64::try_from(row.get::<_, i64>(1)?).map_err(invalid_integer)?,
                    decode_array(row.get(2)?)?,
                    u64::try_from(row.get::<_, i64>(3)?).map_err(invalid_integer)?,
                ))
            })
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let mut retained = Vec::with_capacity(bindings.len());
        for (key_id, version, authority_id, generation) in bindings {
            let binding = ProviderJournalKeyBinding::new(key_id, version, authority_id, generation)
                .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
            if binding != active.binding
                && !retained.iter().any(|key: &ProofKey| key.binding == binding)
            {
                retained.push(load_key(keyring, binding)?);
            }
        }
        Ok(Self { active, retained })
    }

    pub(crate) fn binding(&self) -> ProviderJournalKeyBinding {
        self.active.binding
    }

    pub(crate) fn ensure_current_active(
        &self,
        connection: &Connection,
    ) -> Result<(), ProviderAdmissionError> {
        let durable = connection
            .query_row(
                "SELECT key_id, key_version, runtime_authority_id, database_generation
                 FROM provider_journal_key_refs
                 WHERE state = 1 AND active_slot = 1",
                [],
                |row| {
                    ProviderJournalKeyBinding::new(
                        decode_array(row.get(0)?)?,
                        u64::try_from(row.get::<_, i64>(1)?).map_err(invalid_integer)?,
                        decode_array(row.get(2)?)?,
                        u64::try_from(row.get::<_, i64>(3)?).map_err(invalid_integer)?,
                    )
                    .map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )
            .optional()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if durable == Some(self.binding()) {
            Ok(())
        } else {
            Err(ProviderAdmissionError::AuthorityDenied)
        }
    }

    pub(crate) fn with_retained(mut self, previous: Self) -> Self {
        self.retain(previous.active);
        for key in previous.retained {
            self.retain(key);
        }
        self
    }

    pub(crate) fn issue(
        &self,
        fields: &IssuanceProofFields,
    ) -> Result<[u8; 32], ProviderAdmissionError> {
        if fields.key != self.active.binding {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        Ok(tag(&self.active.key, ISSUANCE_DOMAIN, &fields.encode()))
    }

    pub(crate) fn verify_issue(&self, fields: &IssuanceProofFields, expected: &[u8]) -> bool {
        self.key(fields.key)
            .is_some_and(|key| verify(&key.key, ISSUANCE_DOMAIN, &fields.encode(), expected))
    }

    pub(crate) fn effect(
        &self,
        binding: ProviderJournalKeyBinding,
        fields: &CommittedEffectProofFields,
    ) -> Result<[u8; 32], ProviderAdmissionError> {
        if binding != self.active.binding {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        Ok(tag(&self.active.key, EFFECT_DOMAIN, &fields.encode()))
    }

    pub(crate) fn verify_effect(
        &self,
        binding: ProviderJournalKeyBinding,
        fields: &CommittedEffectProofFields,
        expected: &[u8],
    ) -> bool {
        self.key(binding)
            .is_some_and(|key| verify(&key.key, EFFECT_DOMAIN, &fields.encode(), expected))
    }

    fn key(&self, binding: ProviderJournalKeyBinding) -> Option<&ProofKey> {
        if self.active.binding == binding {
            Some(&self.active)
        } else {
            self.retained.iter().find(|key| key.binding == binding)
        }
    }

    fn retain(&mut self, key: ProofKey) {
        if key.binding != self.active.binding
            && !self
                .retained
                .iter()
                .any(|retained| retained.binding == key.binding)
        {
            self.retained.push(key);
        }
    }
}

fn load_key(
    keyring: &dyn ProviderJournalKeyring,
    binding: ProviderJournalKeyBinding,
) -> Result<ProofKey, ProviderAdmissionError> {
    let key_ref = ProviderJournalKeyRef::new(
        binding.key_id(),
        binding.key_version(),
        binding.runtime_authority_id(),
        binding.database_generation(),
    )
    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let material: ProviderJournalKeyMaterial = keyring
        .load_provider_journal_key(key_ref)
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let key = material.with_bytes(|bytes| Zeroizing::new(bytes.to_vec()));
    Ok(ProofKey { binding, key })
}

fn tag(key: &[u8], domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(encoded);
    mac.finalize().into_bytes().into()
}

fn verify(key: &[u8], domain: &[u8], encoded: &[u8], expected: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(encoded);
    mac.verify_slice(expected).is_ok()
}

fn decode_array<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            bytes.len(),
            rusqlite::types::Type::Blob,
            "invalid proof key binding length".into(),
        )
    })
}

fn invalid_integer(error: std::num::TryFromIntError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error))
}
