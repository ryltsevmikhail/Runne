use runne_application::provider::ProviderAdmissionError;
use runne_provider::ProviderDispatchClaim;
use rusqlite::{Connection, OptionalExtension};

use super::authority_state::RuntimeAuthorityState;

/// Opaque proof that one exact durable runtime launch owns provider effects.
///
/// This value is intentionally neither cloneable nor serializable. Every
/// successful authority activation advances the durable state revision and
/// therefore invalidates capabilities returned by an earlier activation.
pub struct ProviderRuntimeLaunchCapability {
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    generation: u64,
    fence: u64,
    owner: String,
    state_revision: u64,
}

impl ProviderRuntimeLaunchCapability {
    pub(super) fn from_state(
        state: &RuntimeAuthorityState,
    ) -> Result<Self, ProviderAdmissionError> {
        if !state.active
            || state.runtime_authority_id == [0; 16]
            || state.database_generation == 0
            || state.expected_generation == 0
            || state.expected_fencing_token == 0
            || state.owner_id.is_empty()
            || state.state_revision == 0
        {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        Ok(Self {
            runtime_authority_id: state.runtime_authority_id,
            database_generation: state.database_generation,
            generation: state.expected_generation,
            fence: state.expected_fencing_token,
            owner: state.owner_id.clone(),
            state_revision: state.state_revision,
        })
    }

    pub(super) fn verify_state(
        &self,
        state: &RuntimeAuthorityState,
    ) -> Result<(), ProviderAdmissionError> {
        if !state.active
            || self.runtime_authority_id != state.runtime_authority_id
            || self.database_generation != state.database_generation
            || self.generation != state.expected_generation
            || self.generation != state.lease_generation
            || self.fence != state.expected_fencing_token
            || self.fence != state.lease_fencing_token
            || self.owner != state.owner_id
            || self.state_revision != state.state_revision
        {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        Ok(())
    }

    pub(super) fn verify_persisted(
        &self,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        generation: u64,
        fence: u64,
        owner: &str,
        state_revision: u64,
    ) -> Result<(), ProviderAdmissionError> {
        if self.runtime_authority_id != runtime_authority_id
            || self.database_generation != database_generation
            || self.generation != generation
            || self.fence != fence
            || self.owner != owner
            || self.state_revision != state_revision
        {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        Ok(())
    }

    pub(super) fn verify_current_admission(
        &self,
        connection: &Connection,
        claim: &ProviderDispatchClaim,
    ) -> Result<(), ProviderAdmissionError> {
        self.verify_current(connection)?;
        let row = connection
            .query_row(
                "SELECT admission.runtime_authority_id, admission.database_generation,
                        admission.generation, admission.fencing_token,
                        admission.owner_id, admission.authority_revision
                   FROM provider_execution_admissions admission
                  WHERE admission.dispatch_attempt_id = ?1 AND admission.permit_id = ?2
                    AND admission.provider_idempotency_key = ?3
                    AND admission.prepared_digest = ?4 AND admission.render_digest = ?5
                    AND admission.profile_digest = ?6 AND admission.fencing_token = ?7
                    AND admission.token_reservation_id = ?8
                    AND admission.cost_reservation_id = ?9",
                rusqlite::params![
                    claim.attempt_id.as_bytes().as_slice(),
                    claim.permit_id.as_slice(),
                    claim.provider_idempotency_key,
                    claim.prepared_digest.as_slice(),
                    claim.render_digest.as_slice(),
                    claim.profile_digest.as_slice(),
                    to_i64(claim.fencing_token)?,
                    claim.token_reservation_id.as_slice(),
                    claim.cost_reservation_id.as_slice(),
                ],
                |row| {
                    Ok((
                        fixed_16(row.get(0)?)?,
                        positive(row.get(1)?)?,
                        positive(row.get(2)?)?,
                        positive(row.get(3)?)?,
                        row.get::<_, String>(4)?,
                        positive(row.get(5)?)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
            .ok_or(ProviderAdmissionError::StaleFencingToken)?;
        self.verify_persisted(row.0, row.1, row.2, row.3, &row.4, row.5)
    }

    pub(super) fn verify_current(
        &self,
        connection: &Connection,
    ) -> Result<(), ProviderAdmissionError> {
        let row = connection
            .query_row(
                "SELECT runtime_authority_id, database_generation, expected_generation,
                        expected_fencing_token, owner_id, state_revision
                   FROM provider_runtime_authority_state
                  WHERE id = 1 AND active = 1
                    AND expected_generation = lease_generation
                    AND expected_fencing_token = lease_fencing_token",
                [],
                |row| {
                    Ok((
                        fixed_16(row.get(0)?)?,
                        positive(row.get(1)?)?,
                        positive(row.get(2)?)?,
                        positive(row.get(3)?)?,
                        row.get::<_, String>(4)?,
                        positive(row.get(5)?)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
            .ok_or(ProviderAdmissionError::StaleFencingToken)?;
        self.verify_persisted(row.0, row.1, row.2, row.3, &row.4, row.5)
    }
}

fn fixed_16(value: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn to_i64(value: u64) -> Result<i64, ProviderAdmissionError> {
    i64::try_from(value).map_err(|_| ProviderAdmissionError::StaleFencingToken)
}
