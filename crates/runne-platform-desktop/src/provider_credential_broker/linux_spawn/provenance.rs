//! Private spawn-failure provenance for the Linux writer spawn profile.
//!
//! Every `BrokerHandoffError::Unavailable` mapping in the parent-side spawn
//! sequence records the exact failing operation stage plus the numeric raw
//! OS errno carried by the failing error itself (never a `last_os_error`
//! read after intervening calls). The record carries no paths, argv,
//! environment, socket identifiers, or secret material — only the stage
//! name and errno number. The public `BrokerHandoffError` contract is
//! untouched: provenance stays inside the crate and surfaces only through
//! the test-only spawn entry points (panic witnesses and accessors).

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;

/// One instrumented parent-side operation of the spawn sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::provider_credential_broker) enum SpawnOperation {
    PidfdCapabilityProbe,
    DuplicateControl,
    DuplicateHandshake,
    OpenNullWritable,
    DuplicateNullWritable,
    OpenNullReadable,
    SpawnActionsInit,
    SpawnActionsAddDup2,
    SpawnActionsAddClose,
    InventoryReadDir,
    InventoryAddClose,
    SpawnAttrInit,
    SpawnAttrSetFlags,
    PosixSpawn,
}

/// Stage and raw OS errno of one failing spawn operation.
///
/// The fields are read only by the test-only witness below; production
/// carries the record in-band without emitting it anywhere.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpawnProvenance {
    operation: SpawnOperation,
    /// `None` when the failing error carries no OS errno; recorded as
    /// unavailable rather than fabricated.
    os_errno: Option<i32>,
}

/// Private internal failure: the unchanged public error plus provenance.
pub(super) struct SpawnDiagnostic {
    public: BrokerHandoffError,
    provenance: Option<SpawnProvenance>,
}

impl SpawnDiagnostic {
    pub(super) const fn from_raw_errno(operation: SpawnOperation, os_errno: Option<i32>) -> Self {
        Self {
            public: BrokerHandoffError::Unavailable,
            provenance: Some(SpawnProvenance {
                operation,
                os_errno,
            }),
        }
    }

    pub(super) fn unavailable<E: SpawnErrno + ?Sized>(
        operation: SpawnOperation,
        error: &E,
    ) -> Self {
        Self::from_raw_errno(operation, error.spawn_os_errno())
    }

    pub(super) const fn into_public(self) -> BrokerHandoffError {
        self.public
    }
}

impl From<BrokerHandoffError> for SpawnDiagnostic {
    fn from(public: BrokerHandoffError) -> Self {
        Self {
            public,
            provenance: None,
        }
    }
}

/// Extracts the raw OS errno a failing error actually carries, if any.
pub(in crate::provider_credential_broker) trait SpawnErrno {
    fn spawn_os_errno(&self) -> Option<i32>;
}

impl SpawnErrno for std::io::Error {
    fn spawn_os_errno(&self) -> Option<i32> {
        self.raw_os_error()
    }
}

impl SpawnErrno for rustix::io::Errno {
    fn spawn_os_errno(&self) -> Option<i32> {
        Some(self.raw_os_error())
    }
}

impl SpawnErrno for nix::Error {
    fn spawn_os_errno(&self) -> Option<i32> {
        std::io::Error::from(*self).raw_os_error()
    }
}

/// Returns the synthesized failure when the fault injector targets a stage.
/// Production always passes a never-firing injector, so this changes no
/// production behavior; synthetic faults preempt the mapped operation
/// before it runs and never touch real host resources.
pub(super) fn injected(
    fault: &impl Fn(SpawnOperation) -> Option<i32>,
    operation: SpawnOperation,
) -> Option<SpawnDiagnostic> {
    fault(operation).map(|errno| SpawnDiagnostic::from_raw_errno(operation, Some(errno)))
}

/// Test-only witness wrapper: keeps the exact public error while exposing
/// the recorded stage and errno in the failure message of `.expect(...)`
/// on test-only spawn entry points. Never part of the production API.
#[cfg(all(test, target_os = "linux"))]
pub(in crate::provider_credential_broker) struct TestSpawnFailure(pub(super) SpawnDiagnostic);

#[cfg(all(test, target_os = "linux"))]
impl TestSpawnFailure {
    pub(in crate::provider_credential_broker) fn from_error<E: SpawnErrno + ?Sized>(
        operation: SpawnOperation,
        error: &E,
    ) -> Self {
        Self(SpawnDiagnostic::unavailable(operation, error))
    }

    pub(in crate::provider_credential_broker) const fn public_error(&self) -> BrokerHandoffError {
        self.0.public
    }

    pub(in crate::provider_credential_broker) fn operation(&self) -> Option<SpawnOperation> {
        self.0.provenance.map(|provenance| provenance.operation)
    }

    pub(in crate::provider_credential_broker) fn os_errno(&self) -> Option<i32> {
        self.0.provenance.and_then(|p| p.os_errno)
    }
}

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Debug for TestSpawnFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "public={:?}", self.0.public)?;
        if let Some(provenance) = self.0.provenance {
            write!(formatter, " operation={:?}", provenance.operation)?;
            match provenance.os_errno {
                Some(errno) => write!(formatter, " os_errno={errno}"),
                None => write!(formatter, " os_errno=unavailable"),
            }
        } else {
            Ok(())
        }
    }
}
