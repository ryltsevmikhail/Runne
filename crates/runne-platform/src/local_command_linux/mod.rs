//! Fail-closed Linux structured-command gate. Caller owns approval and durable intent.
//! Filesystem and mount controls are enforced here; network policy remains profile-owned.
#![allow(unsafe_code)]

mod child;
mod composite_admission;
mod error;
mod gate;
mod io;
mod permission;
mod policy;
mod snapshot;
mod spec;

pub use composite_admission::LinuxCompositeScopeAdmission;
pub use error::LinuxCommandError;
pub use io::{LinuxCommandOutputChunkV1, LinuxCommandOutputLimitsV1};
pub use permission::{
    BoundPermissionSpecV1, LinuxPermissionOwnerV1, LinuxPermissionPreparationV1,
    PermissionChildTerminalEvidenceV1, PermissionChildV1, PermissionHelperBindingObservationV1,
    PermissionHelperChildV1, PermissionHelperObservationV1, PermissionHelperOperationV1,
    PermissionHelperTargetVersionV1, PermissionHelperTerminalEvidenceV1,
    PermissionTargetObservationV1, PreparedPermissionTargetV1, PreparedToolHelperV1,
};
pub use snapshot::SealedExecutableSnapshot;
pub use spec::{
    GatedLinuxChild, LinuxCommandContainmentV1, LinuxCommandContainmentV2, LinuxCommandExecutable,
    LinuxCommandSpec, LinuxLeaderExitKindV1, LinuxLeaderExitObservationV1,
};
