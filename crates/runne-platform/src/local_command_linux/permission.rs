//! Private-constructor native ownership for retained Linux local commands.

mod bound_spec;
mod child;
mod codec;
mod helper;
mod helper_protocol;
mod helper_types;
mod lineage;
mod release;
mod terminal;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "permission/helper_tests.rs"]
mod helper_tests;

pub use bound_spec::{BoundPermissionSpecV1, PreparedPermissionTargetV1};
pub use child::PermissionChildV1;
pub use helper::{
    PermissionHelperBindingObservationV1, PermissionHelperObservationV1,
    PermissionHelperOperationV1, PermissionHelperTargetVersionV1, PreparedToolHelperV1,
};
pub use lineage::{
    LinuxPermissionOwnerV1, LinuxPermissionPreparationV1, PermissionTargetObservationV1,
};
pub use terminal::{
    PermissionChildTerminalEvidenceV1, PermissionHelperChildV1, PermissionHelperTerminalEvidenceV1,
};

#[cfg(test)]
mod coding_tests;

mod helper_coding;
mod helper_target;
