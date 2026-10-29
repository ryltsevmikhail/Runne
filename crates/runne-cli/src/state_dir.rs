//! Per-user durable state root for the terminal client.
//!
//! Linux uses the XDG state directory. macOS has no XDG state directory, so the
//! user's Application Support directory is the equivalent durable location.

use std::path::PathBuf;

/// Returns the base directory that holds `runne/cli/...` client state.
pub(crate) fn state_root() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|home| home.join("Library/Application Support"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::state_dir()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn state_root_is_absolute_when_available() {
        if let Some(root) = super::state_root() {
            assert!(root.is_absolute(), "state root must be absolute");
            #[cfg(target_os = "macos")]
            assert!(root.ends_with("Library/Application Support"));
        }
    }
}
