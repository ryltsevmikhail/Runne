pub(super) use super::permission_dispatch::{
    PermissionModeExchange, dispatch_permission_mode_request,
};
#[cfg(test)]
pub(super) use super::permission_dispatch::{
    permission_wire_inner_frame, permission_wire_outer_frame,
};

#[cfg(all(test, unix, feature = "desktop-protected"))]
#[path = "permission_request_tests.rs"]
mod tests;
