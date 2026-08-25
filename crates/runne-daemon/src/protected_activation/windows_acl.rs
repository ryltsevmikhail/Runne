//! Owner-only ACL enforcement for the protected runtime root and records.

use std::path::Path;

pub(super) fn enforce_owner_acl(path: &Path) -> bool {
    runne_windows_native_handle::restrict_to_owner(path).is_ok()
}
