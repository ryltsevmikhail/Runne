use std::path::PathBuf;

/// Canonicalizes a user-picked directory path.
/// Only succeeds when called by an explicit user action (caller asserts this).
///
/// # Errors
///
/// Returns an error if the path does not exist, is not a directory, or cannot
/// be canonicalized.
pub fn canonicalize_picked_directory(path: &str) -> Result<PathBuf, String> {
    let p = std::path::Path::new(path);
    if !p.exists() {
        return Err(format!("path does not exist: {path}"));
    }
    if !p.is_dir() {
        return Err(format!("path is not a directory: {path}"));
    }
    p.canonicalize()
        .map_err(|e| format!("cannot resolve path: {e}"))
}

/// Validates an external editor command: executable + exact argv, no shell.
/// Rejects interpolation characters, pipes, redirects.
///
/// # Errors
///
/// Returns an error if the executable name is empty or contains unsafe shell
/// characters (`|`, `;`, `&`, `>`, `<`, `$`, `` ` ``), or if any argument
/// contains such characters.
pub fn validate_external_command(executable: &str, args: &[&str]) -> Result<(), String> {
    if executable.is_empty() {
        return Err("executable name is empty".into());
    }
    for ch in executable.chars() {
        if ch == '|' || ch == ';' || ch == '&' || ch == '>' || ch == '<' || ch == '$' || ch == '`' {
            return Err(format!("executable name contains unsafe character: {ch:?}"));
        }
    }
    for arg in args {
        for ch in arg.chars() {
            if ch == '|'
                || ch == ';'
                || ch == '&'
                || ch == '>'
                || ch == '<'
                || ch == '$'
                || ch == '`'
            {
                return Err(format!("argument contains unsafe character: {ch:?}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityId, PlatformCapabilityProvider, PlatformMatrix};

    #[test]
    fn canonicalize_rejects_nonexistent_path() {
        assert!(canonicalize_picked_directory("/nonexistent/path/12345").is_err());
    }

    #[test]
    fn canonicalize_rejects_file_not_directory() {
        // Use Cargo.toml which exists but is a file
        let result = canonicalize_picked_directory("Cargo.toml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }

    #[test]
    fn validate_rejects_shell_characters() {
        assert!(validate_external_command("echo; rm -rf /", &[]).is_err());
        assert!(validate_external_command("cat", &["file|pipe"]).is_err());
        assert!(validate_external_command("cmd", &["$(malicious)"]).is_err());
    }

    #[test]
    fn validate_accepts_clean_command() {
        assert!(validate_external_command("code", &["--wait", "/path/to/file.rs"]).is_ok());
        assert!(validate_external_command("vim", &[]).is_ok());
    }

    #[test]
    fn diagnostics_redacts_sensitive_values() {
        // Verify that capability diagnostics never expose paths or credentials.
        // This is a compile-time + behavioural check.
        let matrix = PlatformMatrix::desktop();

        // DirectoryPicker is available, but querying availability
        // must not return the actual picked path — only the capability status.
        let diag = format!("{:?}", matrix.availability(CapabilityId::DirectoryPicker));
        assert!(!diag.contains('/'));
        assert!(!diag.contains("Users"));

        // SecureStore availability must not leak any stored value.
        let diag = format!("{:?}", matrix.availability(CapabilityId::SecureStore));
        assert!(!diag.contains("key"));
        assert!(!diag.contains("token"));
    }
}
