//! Seatbelt profile construction for macOS command execution.
//!
//! The profile starts from `deny default`, allows process creation and the
//! system and toolchain roots a program needs to start, confines reads and
//! writes to explicitly admitted roots, and denies network access. Every path
//! is escaped before it reaches SBPL; control characters are rejected rather
//! than silently dropped.

use std::path::{Path, PathBuf};

use crate::containment::ContainmentError;

/// Roots that are readable so ordinary programs and toolchains can start.
const SYSTEM_READ_ROOTS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library/Apple",
    "/Library/Developer",
    "/System/Library/dyld",
    "/private/var/db/dyld",
    "/opt/homebrew",
    "/usr/local",
];

/// Device nodes a process may read without gaining filesystem access.
const DEVICE_READ_LITERALS: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

/// Device nodes a process may write for standard output and diagnostics.
const DEVICE_WRITE_LITERALS: &[&str] = &["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"];

/// Bounds the rendered profile and the number of admitted roots.
const MAX_ROOTS: usize = 64;

/// A workspace-bound Seatbelt profile.
#[derive(Debug, Clone)]
pub struct MacOsSeatbeltProfileV1 {
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
}

impl MacOsSeatbeltProfileV1 {
    /// Builds a profile that reads the system runtime and the workspace and
    /// writes only the workspace.
    ///
    /// # Errors
    /// Returns [`ContainmentError::ProfileUnsupported`] when the workspace is
    /// not an existing directory, is not valid UTF-8, or contains a control
    /// character.
    pub fn new(workspace: &Path) -> Result<Self, ContainmentError> {
        let workspace = canonical_directory(workspace)?;
        let mut profile = Self {
            read_roots: vec![workspace.clone()],
            write_roots: vec![workspace],
        };
        for root in SYSTEM_READ_ROOTS {
            let path = Path::new(root);
            if path.exists() {
                profile.push_read_root(path.to_path_buf())?;
            }
        }
        Ok(profile)
    }

    /// Admits one additional read-only root.
    ///
    /// # Errors
    /// Returns [`ContainmentError::ProfileUnsupported`] when the path is not an
    /// existing directory, cannot be represented in SBPL, or exceeds the root
    /// budget.
    pub fn allow_read_root(&mut self, path: &Path) -> Result<(), ContainmentError> {
        let path = canonical_directory(path)?;
        self.push_read_root(path)
    }

    /// Admits one additional writable root.
    ///
    /// # Errors
    /// Returns [`ContainmentError::ProfileUnsupported`] when the path is not an
    /// existing directory, cannot be represented in SBPL, or exceeds the root
    /// budget.
    pub fn allow_write_root(&mut self, path: &Path) -> Result<(), ContainmentError> {
        let path = canonical_directory(path)?;
        if self.write_roots.len() >= MAX_ROOTS {
            return Err(unsupported("too many writable roots"));
        }
        if !self.write_roots.contains(&path) {
            self.write_roots.push(path);
        }
        Ok(())
    }

    /// Renders the SBPL document consumed by the helper.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::from(
            "(version 1)\n\
             (deny default)\n\
             (deny network*)\n\
             (allow process*)\n\
             (allow sysctl-read)\n\
             (allow file-read-metadata)\n\
             (allow file-read*\n\
             \x20 (literal \"/\")\n",
        );
        for root in &self.read_roots {
            push_rule(&mut output, "subpath", root);
        }
        for literal in DEVICE_READ_LITERALS {
            push_literal(&mut output, literal);
        }
        output.push_str(")\n(allow file-write*\n");
        for root in &self.write_roots {
            push_rule(&mut output, "subpath", root);
        }
        for literal in DEVICE_WRITE_LITERALS {
            push_literal(&mut output, literal);
        }
        output.push_str(")\n");
        output
    }

    fn push_read_root(&mut self, path: PathBuf) -> Result<(), ContainmentError> {
        if self.read_roots.len() >= MAX_ROOTS {
            return Err(unsupported("too many readable roots"));
        }
        if !self.read_roots.contains(&path) {
            self.read_roots.push(path);
        }
        Ok(())
    }
}

fn push_rule(output: &mut String, kind: &str, path: &Path) {
    output.push_str("  (");
    output.push_str(kind);
    output.push_str(" \"");
    output.push_str(&escape(path));
    output.push_str("\")\n");
}

fn push_literal(output: &mut String, literal: &str) {
    output.push_str("  (literal \"");
    output.push_str(literal);
    output.push_str("\")\n");
}

fn escape(path: &Path) -> String {
    let text = path.to_str().expect("paths are validated before rendering");
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    escaped
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ContainmentError> {
    if !path.is_absolute() {
        return Err(unsupported("profile roots must be absolute"));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| unsupported(&format!("cannot resolve {}: {error}", path.display())))?;
    if !canonical.is_dir() {
        return Err(unsupported("profile roots must be directories"));
    }
    let text = canonical
        .to_str()
        .ok_or_else(|| unsupported("profile roots must be valid UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(unsupported(
            "profile roots must not contain control characters",
        ));
    }
    Ok(canonical)
}

fn unsupported(message: &str) -> ContainmentError {
    ContainmentError::ProfileUnsupported(message.to_string())
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;
