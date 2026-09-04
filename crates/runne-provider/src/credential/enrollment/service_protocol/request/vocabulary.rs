use super::super::{
    CredentialMaterial, CredentialServiceCorrelation, CredentialServiceDisposition,
    CredentialServiceEndpointRole, CredentialServiceEpoch, CredentialServiceRequestSequence,
};
use super::surfaces::{
    CredentialMetadataReadbackAdmission, CredentialMetadataReadbackRequest,
    CredentialPointOfUseReadAdmission, CredentialPointOfUseReadRequest,
};
use super::{
    CredentialRuntimeMutationAdmission, CredentialRuntimeMutationArmRequest,
    CredentialWriterConsumeRequest, CredentialWriterIngressRequest,
};

/// Closed outbound vocabulary for all service endpoints.
pub enum CredentialServiceRequest {
    /// Payload-free Desktop challenge request.
    RegistrationChallenge,
    /// Runtime mutation arm.
    RuntimeMutationArm(CredentialRuntimeMutationArmRequest),
    /// Authenticated writer consume.
    WriterConsume(CredentialWriterConsumeRequest),
    /// Runtime metadata readback.
    MetadataReadback(CredentialMetadataReadbackRequest),
    /// Runtime point-of-use read.
    PointOfUseRead(CredentialPointOfUseReadRequest),
}

/// Closed syntax-only service ingress vocabulary.
pub enum CredentialServiceIngressRequest {
    /// Payload-free Desktop challenge request.
    RegistrationChallenge,
    /// Decoded mutation admission.
    RuntimeMutationArm(CredentialRuntimeMutationAdmission),
    /// Decoded writer ingress.
    WriterConsume(CredentialWriterIngressRequest),
    /// Decoded metadata read.
    MetadataReadback(CredentialMetadataReadbackAdmission),
    /// Decoded point-of-use read.
    PointOfUseRead(CredentialPointOfUseReadAdmission),
}

macro_rules! endpoint_role {
    ($name:ident) => {
        impl $name {
            /// Returns the code-owned listener role.
            pub const fn endpoint_role(&self) -> CredentialServiceEndpointRole {
                match self {
                    Self::RegistrationChallenge => CredentialServiceEndpointRole::Desktop,
                    Self::WriterConsume(_) => CredentialServiceEndpointRole::Writer,
                    Self::RuntimeMutationArm(_)
                    | Self::MetadataReadback(_)
                    | Self::PointOfUseRead(_) => CredentialServiceEndpointRole::Runtime,
                }
            }
        }
    };
}
endpoint_role!(CredentialServiceRequest);
endpoint_role!(CredentialServiceIngressRequest);

/// Code-owned request operation used to bind the exact reply vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialServiceRequestKind {
    /// Payload-free Desktop challenge.
    RegistrationChallenge,
    /// Runtime mutation arm.
    RuntimeMutationArm,
    /// One-shot writer consume.
    WriterConsume,
    /// Runtime metadata read.
    MetadataReadback,
    /// Runtime point-of-use read.
    PointOfUseRead,
}

/// Non-secret exact request identity copied into the canonical reply frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialServiceRequestContext {
    pub(crate) role: CredentialServiceEndpointRole,
    pub(crate) kind: CredentialServiceRequestKind,
    pub(crate) epoch: Option<CredentialServiceEpoch>,
    pub(crate) sequence: Option<CredentialServiceRequestSequence>,
    pub(crate) correlation: Option<CredentialServiceCorrelation>,
}

macro_rules! request_context {
    ($name:ident) => {
        impl $name {
            /// Returns the exact code-owned reply context for this request.
            pub fn context(&self) -> CredentialServiceRequestContext {
                match self {
                    Self::RegistrationChallenge => CredentialServiceRequestContext::desktop(),
                    Self::RuntimeMutationArm(value) => CredentialServiceRequestContext::bound(
                        CredentialServiceEndpointRole::Runtime,
                        CredentialServiceRequestKind::RuntimeMutationArm,
                        value.epoch(),
                        value.sequence(),
                        value.correlation(),
                    ),
                    Self::WriterConsume(value) => CredentialServiceRequestContext::bound(
                        CredentialServiceEndpointRole::Writer,
                        CredentialServiceRequestKind::WriterConsume,
                        value.binding().epoch,
                        value.binding().sequence,
                        value.binding().correlation,
                    ),
                    Self::MetadataReadback(value) => CredentialServiceRequestContext::bound(
                        CredentialServiceEndpointRole::Runtime,
                        CredentialServiceRequestKind::MetadataReadback,
                        value.binding().epoch(),
                        value.binding().sequence(),
                        value.binding().correlation(),
                    ),
                    Self::PointOfUseRead(value) => CredentialServiceRequestContext::bound(
                        CredentialServiceEndpointRole::Runtime,
                        CredentialServiceRequestKind::PointOfUseRead,
                        value.binding().epoch(),
                        value.binding().sequence(),
                        value.binding().correlation(),
                    ),
                }
            }
        }
    };
}
request_context!(CredentialServiceRequest);
request_context!(CredentialServiceIngressRequest);

impl CredentialServiceRequestContext {
    const fn desktop() -> Self {
        Self {
            role: CredentialServiceEndpointRole::Desktop,
            kind: CredentialServiceRequestKind::RegistrationChallenge,
            epoch: None,
            sequence: None,
            correlation: None,
        }
    }

    const fn bound(
        role: CredentialServiceEndpointRole,
        kind: CredentialServiceRequestKind,
        epoch: CredentialServiceEpoch,
        sequence: CredentialServiceRequestSequence,
        correlation: CredentialServiceCorrelation,
    ) -> Self {
        Self {
            role,
            kind,
            epoch: Some(epoch),
            sequence: Some(sequence),
            correlation: Some(correlation),
        }
    }
}

/// Closed reply vocabulary; errors contain only disposition.
pub enum CredentialServiceReply {
    /// Exact imported version exists, with this persisted nonzero source revision.
    LegacyMetadata {
        /// Nonzero revision of the source copied into the immutable destination.
        source_revision: [u8; 16],
    },
    /// Service-issued challenge reply.
    RegistrationChallenge {
        /// Current epoch.
        epoch: CredentialServiceEpoch,
        /// Random nonce.
        nonce: [u8; 16],
    },
    /// Runtime arm accepted.
    Armed,
    /// Writer grant consumed before native effect.
    Consumed,
    /// Non-secret metadata result.
    Metadata {
        /// Whether exact version exists.
        present: bool,
    },
    /// Point-of-use material reply.
    Material(CredentialMaterial),
    /// Closed rejection.
    Rejected(CredentialServiceDisposition),
}

/// Reconciliation-only proof for session loss; it cannot become an arm.
pub struct CredentialServiceReconciliationRequired {
    current_epoch: CredentialServiceEpoch,
}

impl CredentialServiceReconciliationRequired {
    /// Returns epoch needed for bounded rejoin.
    pub const fn current_epoch(&self) -> CredentialServiceEpoch {
        self.current_epoch
    }
}

impl CredentialServiceReply {
    /// Extracts only the reconciliation transition from SessionMissing.
    pub fn into_reconciliation(self) -> Result<CredentialServiceReconciliationRequired, Self> {
        match self {
            Self::Rejected(CredentialServiceDisposition::SessionMissing { current_epoch }) => {
                Ok(CredentialServiceReconciliationRequired { current_epoch })
            }
            other => Err(other),
        }
    }
}
