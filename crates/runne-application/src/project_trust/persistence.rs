use super::{
    ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus, TrustPersistenceError,
    TrustToken,
};

/// Owned durable lease keeping one project trust record current until drop.
/// Implementations must retain the persistence write fence for the lease's
/// lifetime; unsupported authorities fail closed instead of returning a
/// snapshot that could become stale before an effect starts.
pub trait ProjectTrustEffectLease: Send {
    /// The immutable record checked while the persistence fence is held.
    fn record(&self) -> ProjectTrustRecord;
}

/// Administrative trust-control lease. It holds the same durable writer
/// fence through canonical binding validation and a user-authorized CAS.
pub trait ProjectTrustControlLease: Send {
    /// Current record observed under the writer fence.
    fn record(&self) -> ProjectTrustRecord;
    /// Commits only a user-controlled trusted/untrusted decision under this
    /// already-held lease. Managed policy is never writable through this port.
    fn decide(
        &mut self,
        trusted: bool,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError>;
}

/// Runtime-owned durable trust persistence port.
pub trait ProjectTrustPersistence: Send + Sync {
    /// Loads the durable record; absent rows read as
    /// [`ProjectTrustRecord::untrusted_default`] bound to the current
    /// instance epoch.
    fn load(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError>;

    /// Whether the project carries an explicitly committed trust row.
    fn has_explicit_record(
        &self,
        project: ProjectTrustProjectId,
    ) -> Result<bool, TrustPersistenceError>;

    /// Instance epoch of the durable sidecar (0 only when unavailable).
    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError>;

    /// Acquires a durable write fence and returns the current project record.
    /// The default is fail-closed for stores unable to arbitrate revocation
    /// against a provider effect-start boundary.
    fn acquire_effect_lease(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, TrustPersistenceError> {
        Err(TrustPersistenceError::Unavailable)
    }

    /// Acquires the writer fence for safe metadata read and explicit user
    /// trust control. Unsupported stores fail closed.
    fn acquire_control_lease(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<Box<dyn ProjectTrustControlLease>, TrustPersistenceError> {
        Err(TrustPersistenceError::Unavailable)
    }

    /// Compare-and-set status/mask with an epoch-scoped monotonic revision.
    /// `expected.revision == 0` inserts the first row as revision `1` and is
    /// only valid while `expected.instance_epoch` is current.
    fn commit(
        &self,
        project: ProjectTrustProjectId,
        status: ProjectTrustStatus,
        managed_deny_mask: u32,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError>;
}
