use runne_provider::CredentialVersionRef;
use runne_provider::{CredentialBrokerCommand, CredentialMaterial};

/// Closed result emitted by a platform credential backend.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialBackendResult<T = ()> {
    /// The requested native state was observed.
    Observed(T),
    /// The exact native item is absent.
    Absent,
    /// Native policy denied access.
    AccessDenied,
    /// The installed platform profile cannot perform the operation.
    Unsupported,
    /// The backend is temporarily unavailable.
    Unavailable,
    /// The native effect may have happened and requires reconciliation.
    Uncertain,
}

/// One mutation passed to the public closure seam for the platform adapter.
pub struct CredentialMutationEffect<'a> {
    command: &'a CredentialBrokerCommand,
    material: Option<CredentialMaterial>,
}

/// One authenticated runtime read passed to the public platform closure seam.
pub enum CredentialRuntimeReadEffect<'a> {
    /// Metadata-only exact version lookup.
    Metadata(&'a CredentialVersionRef),
    /// Dispatch-bound point-of-use material lookup.
    PointOfUse(&'a CredentialVersionRef),
}

/// Closed observation returned by the runtime read closure.
pub enum CredentialRuntimeReadObservation {
    /// Metadata lookup result.
    Metadata(CredentialBackendResult<()>),
    /// Point-of-use lookup result.
    PointOfUse(CredentialBackendResult<CredentialMaterial>),
}

impl<'a> CredentialMutationEffect<'a> {
    pub(crate) const fn new(
        command: &'a CredentialBrokerCommand,
        material: Option<CredentialMaterial>,
    ) -> Self {
        Self { command, material }
    }

    /// Returns the exact non-secret durable command identity.
    #[must_use]
    pub const fn command(&self) -> &CredentialBrokerCommand {
        self.command
    }

    /// Moves secret material into the native effect implementation.
    #[must_use]
    pub fn into_material(self) -> Option<CredentialMaterial> {
        self.material
    }
}

trait MutationBackend {
    fn execute(self, effect: CredentialMutationEffect<'_>) -> CredentialBackendResult<()>;
}

impl<F> MutationBackend for F
where
    F: FnOnce(CredentialMutationEffect<'_>) -> CredentialBackendResult<()>,
{
    fn execute(self, effect: CredentialMutationEffect<'_>) -> CredentialBackendResult<()> {
        self(effect)
    }
}

pub fn execute_mutation(
    backend: impl FnOnce(CredentialMutationEffect<'_>) -> CredentialBackendResult<()>,
    effect: CredentialMutationEffect<'_>,
) -> CredentialBackendResult<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.execute(effect)))
        .unwrap_or(CredentialBackendResult::Uncertain)
}

trait ReadBackend {
    fn execute(self, effect: CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation;
}

impl<F> ReadBackend for F
where
    F: FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
{
    fn execute(self, effect: CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation {
        self(effect)
    }
}

pub fn execute_read(
    backend: impl FnOnce(CredentialRuntimeReadEffect<'_>) -> CredentialRuntimeReadObservation,
    effect: CredentialRuntimeReadEffect<'_>,
) -> Option<CredentialRuntimeReadObservation> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.execute(effect))).ok()
}
