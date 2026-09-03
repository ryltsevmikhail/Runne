mod admission_registry;
mod begin;
pub(crate) mod broker;
mod control_exchange;
#[cfg(test)]
mod control_exchange_tests;
mod control_facade;
mod coordinator;
mod effect_authority;
mod host;
mod http_admission_resolver;
mod operation_handle;
mod operation_projection;
mod projection;
mod readback;
mod recovery;
mod resume;
mod status;
mod verified_frames;

#[cfg(any(test, feature = "desktop-protected"))]
pub(crate) use control_facade::DaemonProtectedCredentialEnrollmentSession;
pub(crate) use control_facade::DaemonProviderCredentialEnrollmentControl;
pub(crate) use coordinator::ProviderCredentialAdmission;
use effect_authority::ProviderCredentialEffectAuthority;
pub(crate) use host::ProviderCredentialVerificationHost;
pub(crate) use operation_handle::ProviderCredentialOperationHandleIssuer;
pub(crate) use readback::CredentialEnrollmentReadback;
pub(crate) use recovery::CredentialEnrollmentRecoveryGateway;
#[cfg(test)]
use recovery::WriterExitDiagnostic;
#[allow(unused_imports)]
pub(crate) use status::ProviderCredentialEnrollmentStatus;

#[cfg(test)]
mod tests;
