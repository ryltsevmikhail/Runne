#[path = "permission_native_ui/bridge.rs"]
mod bridge;
#[path = "permission_native_ui/coordinator.rs"]
mod coordinator;
#[path = "permission_native_ui/gtk_dialog.rs"]
mod gtk_dialog;

#[expect(
    clippy::redundant_pub_crate,
    reason = "The native UI worker is intentionally exposed only within the app crate."
)]
pub(crate) use coordinator::start;
