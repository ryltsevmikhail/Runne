// Owner-only ACLs for mutable protected runtime state on Windows.

/// Applies a protected DACL granting full access only to the object owner and
/// the operating system. The object owner is inherited from the creating user;
/// a caller that cannot retain that owner fails closed.
fn restrict_to_owner(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    runne_windows_native_handle::restrict_to_owner(path)
        .map_err(|_| ProtectedBundledRuntimeError::RuntimeRootUnavailable)
}

fn validate_private_path(path: &Path) -> Result<(), ProtectedBundledRuntimeError> {
    restrict_to_owner(path)
}
