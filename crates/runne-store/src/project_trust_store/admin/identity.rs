use runne_application::project_trust::admin::{
    AdminError, AuthenticatedPolicyAdminSubject, CurrentPolicyAdmin, VerifiedPolicyAdminBootstrap,
    policy_admin_stable_identity_digest,
};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AdminIdentity {
    pub(super) stable_digest: [u8; 32],
    pub(super) authority_id: [u8; 16],
    pub(super) principal_id: String,
    pub(super) lineage_id: [u8; 16],
    pub(super) profile_id: String,
    pub(super) schema_hash: [u8; 32],
    pub(super) capability_digest: [u8; 32],
    pub(super) provenance: [u8; 32],
}

impl AdminIdentity {
    pub(super) fn from_current(current: &CurrentPolicyAdmin<'_>) -> Self {
        Self::from_subject(
            &current.authenticated_subject(),
            *current.installation_provenance(),
        )
    }

    pub(super) fn from_subject(
        subject: &AuthenticatedPolicyAdminSubject<'_>,
        provenance: [u8; 32],
    ) -> Self {
        Self {
            stable_digest: policy_admin_stable_identity_digest(subject),
            authority_id: *subject.authority_id(),
            principal_id: subject.principal_id().to_owned(),
            lineage_id: *subject.lineage_id(),
            profile_id: subject.profile_id().to_owned(),
            schema_hash: *subject.schema_hash(),
            capability_digest: *subject.capability_digest(),
            provenance,
        }
    }

    pub(super) fn from_registration(
        current: &CurrentPolicyAdmin<'_>,
        bootstrap: &VerifiedPolicyAdminBootstrap,
    ) -> Result<Self, AdminError> {
        if current.binding() != bootstrap.binding()
            || current.installation_provenance() != bootstrap.installation_provenance()
        {
            return Err(AdminError::Rejected);
        }
        Ok(Self::from_current(current))
    }

    pub(super) fn matches_current(&self, current: &CurrentPolicyAdmin<'_>) -> bool {
        *self == Self::from_current(current)
    }

    pub(super) fn matches_subject(&self, subject: &AuthenticatedPolicyAdminSubject<'_>) -> bool {
        self.stable_digest == policy_admin_stable_identity_digest(subject)
            && self.authority_id == *subject.authority_id()
            && self.lineage_id == *subject.lineage_id()
            && self.principal_id == subject.principal_id()
            && self.profile_id == subject.profile_id()
            && self.schema_hash == *subject.schema_hash()
            && self.capability_digest == *subject.capability_digest()
    }

    pub(super) fn insert(
        &self,
        connection: &Connection,
        generation: u64,
        now: i64,
    ) -> Result<(), AdminError> {
        connection
            .execute(
                "INSERT INTO managed_policy_administrator
             (id, stable_subject_digest, authority_id, principal_id, lineage_id, profile_id,
              schema_hash, capability_digest, installation_provenance_digest, role,
              generation, status, registered_at_unix_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, 1, ?10)",
                params![
                    self.stable_digest.as_slice(),
                    self.authority_id.as_slice(),
                    self.principal_id,
                    self.lineage_id.as_slice(),
                    self.profile_id,
                    self.schema_hash.as_slice(),
                    self.capability_digest.as_slice(),
                    self.provenance.as_slice(),
                    i64::try_from(generation).map_err(|_| AdminError::Unavailable)?,
                    now
                ],
            )
            .map_err(|_| AdminError::Conflict)?;
        Ok(())
    }

    pub(super) fn load_registered(
        connection: &Connection,
    ) -> Result<Option<(Self, i64, i64)>, AdminError> {
        let raw = connection.query_row(
            "SELECT stable_subject_digest, authority_id, principal_id, lineage_id, profile_id,
                    schema_hash, capability_digest, installation_provenance_digest, status, generation
             FROM managed_policy_administrator WHERE id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?, row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?, row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?)),
        ).optional().map_err(|_| AdminError::Unavailable)?;
        raw.map(|r| {
            Ok((
                Self {
                    stable_digest: fixed(r.0)?,
                    authority_id: fixed(r.1)?,
                    principal_id: r.2,
                    lineage_id: fixed(r.3)?,
                    profile_id: r.4,
                    schema_hash: fixed(r.5)?,
                    capability_digest: fixed(r.6)?,
                    provenance: fixed(r.7)?,
                },
                r.8,
                r.9,
            ))
        })
        .transpose()
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], AdminError> {
    value.try_into().map_err(|_| AdminError::Unavailable)
}
