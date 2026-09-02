use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialEnrollmentError,
    CredentialRuntimeArmAuthority,
};

use super::{
    CredentialMutationGrantDigest, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceRequestSequence,
};

mod surfaces;
mod vocabulary;
mod writer;
pub use surfaces::{
    CredentialMetadataReadbackAdmission, CredentialMetadataReadbackRequest,
    CredentialPointOfUseReadAdmission, CredentialPointOfUseReadRequest,
    CredentialRuntimeReadBinding,
};
pub use vocabulary::{
    CredentialServiceIngressRequest, CredentialServiceReconciliationRequired,
    CredentialServiceReply, CredentialServiceRequest, CredentialServiceRequestContext,
    CredentialServiceRequestKind,
};
pub use writer::{CredentialWriterConsumeRequest, CredentialWriterIngressRequest};

/// Canonical move-only mutation arm issued only by process-local runtime authority.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialRuntimeMutationArmRequest>();
/// ```
pub struct CredentialRuntimeMutationArmRequest(pub(super) CredentialRuntimeMutationBinding);

/// Move-only authorized plan split into runtime and writer one-shot handoffs.
pub struct CredentialRuntimeMutationPlan(CredentialRuntimeMutationBinding);

/// Move-only service binding delivered to the authenticated writer handoff.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialWriterServiceBindingHandoff>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialWriterServiceBindingHandoff>();
/// ```
pub struct CredentialWriterServiceBindingHandoff(pub(super) CredentialRuntimeMutationBinding);

/// Service-ingress mutation admission decoded without minting runtime issue authority.
pub struct CredentialRuntimeMutationAdmission(pub(super) CredentialRuntimeMutationBinding);

#[derive(Clone, Debug)]
pub(crate) struct CredentialRuntimeMutationBinding {
    pub(super) command: CredentialBrokerCommand,
    pub(super) epoch: CredentialServiceEpoch,
    pub(super) installation_owner: [u8; 32],
    pub(super) session: [u8; 16],
    pub(super) runtime_generation: u64,
    pub(super) release_binding: CredentialBindingDigest,
    pub(super) sequence: CredentialServiceRequestSequence,
    pub(super) correlation: CredentialServiceCorrelation,
    pub(super) deadline: CredentialServiceDeadline,
    pub(super) grant_digest: CredentialMutationGrantDigest,
}

impl PartialEq for CredentialRuntimeMutationBinding {
    fn eq(&self, other: &Self) -> bool {
        self.command == other.command
            && self.epoch == other.epoch
            && self.installation_owner == other.installation_owner
            && self.session == other.session
            && self.runtime_generation == other.runtime_generation
            && self.release_binding == other.release_binding
            && self.sequence == other.sequence
            && self.correlation == other.correlation
            && self.deadline == other.deadline
            && self.grant_digest.ct_matches(other.grant_digest)
    }
}

impl Eq for CredentialRuntimeMutationBinding {}

macro_rules! mutation_accessors {
    ($name:ident) => {
        impl $name {
            /// Returns the exact broker command identity.
            pub const fn command(&self) -> &CredentialBrokerCommand {
                &self.0.command
            }
            /// Returns the service epoch.
            pub const fn epoch(&self) -> CredentialServiceEpoch {
                self.0.epoch
            }
            /// Returns the installation owner routed by the authenticated envelope.
            pub const fn installation_owner(&self) -> [u8; 32] {
                self.0.installation_owner
            }
            /// Returns the protected session identity.
            pub const fn session(&self) -> [u8; 16] {
                self.0.session
            }
            /// Returns the runtime generation.
            pub const fn runtime_generation(&self) -> u64 {
                self.0.runtime_generation
            }
            /// Returns the exact installed release binding.
            pub const fn release_binding(&self) -> CredentialBindingDigest {
                self.0.release_binding
            }
            /// Returns the session-scoped sequence.
            pub const fn sequence(&self) -> CredentialServiceRequestSequence {
                self.0.sequence
            }
            /// Returns the exact request correlation.
            pub const fn correlation(&self) -> CredentialServiceCorrelation {
                self.0.correlation
            }
            /// Returns the bounded deadline.
            pub const fn deadline(&self) -> CredentialServiceDeadline {
                self.0.deadline
            }
            /// Returns the one-use grant digest.
            pub const fn grant_digest(&self) -> CredentialMutationGrantDigest {
                self.0.grant_digest
            }
        }
    };
}
mutation_accessors!(CredentialRuntimeMutationArmRequest);
mutation_accessors!(CredentialRuntimeMutationAdmission);

impl CredentialRuntimeMutationPlan {
    /// Issues one plan under process-local runtime authority.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        _authority: &CredentialRuntimeArmAuthority,
        command: CredentialBrokerCommand,
        epoch: CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
        deadline: CredentialServiceDeadline,
        grant_digest: CredentialMutationGrantDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self(CredentialRuntimeMutationBinding::new(
            command,
            epoch,
            installation_owner,
            session,
            runtime_generation,
            release_binding,
            sequence,
            correlation,
            deadline,
            grant_digest,
        )?))
    }

    /// Splits the authorized plan into independent move-only transports.
    pub fn split(
        self,
    ) -> (
        CredentialRuntimeMutationArmRequest,
        CredentialWriterServiceBindingHandoff,
    ) {
        (
            CredentialRuntimeMutationArmRequest(self.0.clone()),
            CredentialWriterServiceBindingHandoff(self.0),
        )
    }
}

impl CredentialRuntimeMutationBinding {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        command: CredentialBrokerCommand,
        epoch: CredentialServiceEpoch,
        installation_owner: [u8; 32],
        session: [u8; 16],
        runtime_generation: u64,
        release_binding: CredentialBindingDigest,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
        deadline: CredentialServiceDeadline,
        grant_digest: CredentialMutationGrantDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        if installation_owner == [0; 32] || session == [0; 16] || runtime_generation == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            command,
            epoch,
            installation_owner,
            session,
            runtime_generation,
            release_binding,
            sequence,
            correlation,
            deadline,
            grant_digest,
        })
    }
}
