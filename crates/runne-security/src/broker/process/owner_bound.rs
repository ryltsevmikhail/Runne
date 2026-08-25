use runne_platform_ports::process::{ProcessLifecycleBindingV1, ProcessPlatformRequestV1};
#[cfg(test)]
use runne_platform_ports::process::{
    HeldFileIdentityV1, ProcessFileKindV1, ProcessSymlinkProofV1, VerifiedCwdV1,
    VerifiedExecutableV1,
};
use std::fmt;
use uuid::Uuid;
/// Input for one owner-bound structured process launch.
pub struct OwnerBoundProcessRequest {
    spec: ProcessSpec,
    prepared: ProcessPlatformRequestV1,
    binding: ProcessLifecycleBindingV1,
    invocation: ProcessInvocationIdV1,
}
/// Opaque invocation identity bound to one process launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessInvocationIdV1([u8; 16]);
impl ProcessInvocationIdV1 {
    /// Creates a non-zero invocation identity.
    pub fn new(value: [u8; 16]) -> Result<Self, OwnerBoundProcessError> {
        (value != [0; 16])
            .then_some(Self(value))
            .ok_or(OwnerBoundProcessError::InvalidInvocationIdentity)
    }

    /// Returns the opaque invocation bytes for registry keying.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}
impl OwnerBoundProcessRequest {
    /// Creates a request from verified executable/cwd platform identities.
    pub fn new_prepared(
        spec: ProcessSpec,
        prepared: ProcessPlatformRequestV1,
        binding: ProcessLifecycleBindingV1,
        invocation: ProcessInvocationIdV1,
    ) -> Result<Self, OwnerBoundProcessError> {
        if spec.executable_digest != Some(*prepared.executable().identity().content_digest()) {
            return Err(OwnerBoundProcessError::PreparedInvocationInvalid);
        }
        Ok(Self {
            spec,
            prepared,
            binding,
            invocation,
        })
    }

    /// Returns the canonical digest used to identify this exact launch intent.
    #[must_use]
    pub fn intent_digest(&self) -> [u8; 32] {
        process_intent_digest(&self.spec, &self.prepared)
    }

    #[cfg(test)]
    fn new(
        spec: ProcessSpec,
        binding: ProcessLifecycleBindingV1,
        invocation: ProcessInvocationIdV1,
    ) -> Self {
        let prepared = test_prepared_request(spec.executable_digest.unwrap_or([1; 32]));
        Self::new_prepared(spec, prepared, binding, invocation).expect("prepared request")
    }
}

#[cfg(test)]
fn test_prepared_request(content_digest: [u8; 32]) -> ProcessPlatformRequestV1 {
    let executable = VerifiedExecutableV1::new(
        HeldFileIdentityV1::new([1; 16], [2; 32], content_digest, [3; 32], 1).unwrap(),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        HeldFileIdentityV1::new([4; 16], [5; 32], [6; 32], [7; 32], 1).unwrap(),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    ProcessPlatformRequestV1::new([8; 32], executable, cwd).unwrap()
}
/// Exact launch input passed to a native process adapter.
pub struct OwnerBoundProcessLaunchRequest<'a> {
    spec: &'a ProcessSpec,
    prepared: &'a ProcessPlatformRequestV1,
    binding: &'a ProcessLifecycleBindingV1,
    invocation: ProcessInvocationIdV1,
    launch_nonce: [u8; 16],
}

impl OwnerBoundProcessLaunchRequest<'_> {
    /// Returns the verified executable/cwd platform preparation.
    #[must_use]
    pub const fn prepared(&self) -> &ProcessPlatformRequestV1 {
        self.prepared
    }

    /// Returns the structured non-path arguments for native launch.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.spec.argv
    }

    /// Returns the bounded environment for native launch.
    #[must_use]
    pub fn environment(&self) -> &std::collections::HashMap<String, String> {
        &self.spec.env
    }

    /// Returns the validated launch timeout.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.spec.timeout_ms
    }

    /// Returns the exact lifecycle binding.
    #[must_use]
    pub fn binding(&self) -> &ProcessLifecycleBindingV1 {
        self.binding
    }

    /// Returns the exact invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> ProcessInvocationIdV1 {
        self.invocation
    }

    /// Returns the one-time launch nonce.
    #[must_use]
    pub const fn launch_nonce(&self) -> &[u8; 16] {
        &self.launch_nonce
    }
}

/// Native observation required to establish an owned process handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLaunchObservationV1 {
    pid: u32,
    start_identity: [u8; 32],
}

impl ProcessLaunchObservationV1 {
    /// Creates an observation with non-zero PID and start identity.
    pub fn new(pid: u32, start_identity: [u8; 32]) -> Result<Self, OwnerBoundProcessError> {
        if pid == 0 || start_identity == [0; 32] {
            return Err(OwnerBoundProcessError::InvalidLaunchIdentity);
        }
        Ok(Self {
            pid,
            start_identity,
        })
    }
}

/// Opaque runtime-owned process handle used for exact stop authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct OwnedProcessHandleV1 {
    binding: ProcessLifecycleBindingV1,
    invocation: ProcessInvocationIdV1,
    pid: u32,
    start_identity: [u8; 32],
    launch_nonce: [u8; 16],
}

impl fmt::Debug for OwnedProcessHandleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedProcessHandleV1(redacted)")
    }
}

impl OwnedProcessHandleV1 {
    /// Reconstructs an exact handle from durable runtime ownership material.
    pub fn recovered(
        binding: ProcessLifecycleBindingV1,
        invocation: ProcessInvocationIdV1,
        pid: u32,
        start_identity: [u8; 32],
        launch_nonce: [u8; 16],
    ) -> Result<Self, OwnerBoundProcessError> {
        if pid == 0 || start_identity == [0; 32] || launch_nonce == [0; 16] {
            return Err(OwnerBoundProcessError::InvalidLaunchIdentity);
        }
        Ok(Self {
            binding,
            invocation,
            pid,
            start_identity,
            launch_nonce,
        })
    }

    /// Returns the exact lifecycle binding without exposing a native handle.
    #[must_use]
    pub const fn binding(&self) -> &ProcessLifecycleBindingV1 {
        &self.binding
    }

    /// Returns the exact invocation identity.
    #[must_use]
    pub const fn invocation(&self) -> ProcessInvocationIdV1 {
        self.invocation
    }

    /// Returns the observed operating-system process identifier.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the platform start identity used to reject PID reuse.
    #[must_use]
    pub const fn start_identity(&self) -> &[u8; 32] {
        &self.start_identity
    }

    /// Returns the one-time launch nonce.
    #[must_use]
    pub const fn launch_nonce(&self) -> &[u8; 16] {
        &self.launch_nonce
    }
}

/// Closed error for owner-bound process lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnerBoundProcessError {
    /// The legacy structured process policy rejected the request.
    #[error("process request rejected")]
    ProcessRejected,
    /// Containment admission did not complete.
    #[error("process containment admission failed")]
    ContainmentUnavailable,
    /// The native adapter returned an unusable PID or start identity.
    #[error("process launch identity is invalid")]
    InvalidLaunchIdentity,
    /// The invocation identity was empty or malformed.
    #[error("process invocation identity is invalid")]
    InvalidInvocationIdentity,
    /// The native adapter refused to launch or stop the exact process.
    #[error("process lifecycle operation rejected")]
    LifecycleRejected,
    /// The raw specification did not match verified platform identities.
    #[error("prepared process invocation is invalid")]
    PreparedInvocationInvalid,
    /// A launch key is active with a different intent digest.
    #[error("process launch intent conflicts with an active lifecycle")]
    IntentConflict,
    /// Durable adoption did not provide a canonical launch intent digest.
    #[error("process launch intent digest is invalid")]
    InvalidIntentDigest,
    /// The supplied owner, PID, start identity or nonce did not match.
    #[error("process ownership does not match")]
    OwnershipMismatch,
    /// The exact launch handle has already been successfully stopped.
    #[error("process is already stopped")]
    ProcessAlreadyStopped,
    /// The broker could not access its ownership registry.
    #[error("process ownership registry unavailable")]
    RegistryUnavailable,
}

/// Native adapter with no shell or identifier-only stop operation.
pub trait OwnerBoundProcessLauncher: Send + Sync {
    /// Starts the exact structured request and returns verified native identity.
    fn launch(
        &self,
        request: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError>;

    /// Stops only the exact PID/start-identity/nonce tuple.
    fn stop(&self, handle: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError>;
}

#[cfg(test)]
mod owner_bound_tests {
    include!("owner_bound_tests.rs");
}
