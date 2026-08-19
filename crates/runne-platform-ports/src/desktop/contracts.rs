use std::path::PathBuf;

/// Native Windows ACL facts required before an owner-only runtime artifact can
/// be admitted. A future backend must populate these facts from an opened
/// handle, not from a path-only metadata lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAclObjectKind {
    /// Opened handle identifies a direct regular file.
    DirectFile,
    /// Opened handle or final path contains a reparse point.
    ReparsePoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAclOwner {
    /// Owner SID exactly matches the current native principal.
    CurrentPrincipal,
    /// Owner SID is missing or belongs to another principal.
    OtherPrincipal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsDaclShape {
    /// DACL is present, non-null, protected and contains explicit ACEs only.
    ProtectedExplicit,
    /// DACL is missing or null.
    MissingOrNull,
    /// DACL inherits access or otherwise is not protected.
    UnprotectedOrInherited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsOwnerAccess {
    /// Current principal retains the required complete access.
    FullControl,
    /// Current principal does not retain the required complete access.
    Insufficient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsUnexpectedTrusteeAccess {
    /// No allow ACE grants access beyond current principal and `LocalSystem`.
    Absent,
    /// An allow ACE grants access to another trustee.
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsOwnerAclProbeV1 {
    object_kind: WindowsAclObjectKind,
    owner: WindowsAclOwner,
    dacl: WindowsDaclShape,
    owner_access: WindowsOwnerAccess,
    unexpected_trustee_access: WindowsUnexpectedTrusteeAccess,
}

impl WindowsOwnerAclProbeV1 {
    #[must_use]
    pub const fn new(
        object_kind: WindowsAclObjectKind,
        owner: WindowsAclOwner,
        dacl: WindowsDaclShape,
        owner_access: WindowsOwnerAccess,
        unexpected_trustee_access: WindowsUnexpectedTrusteeAccess,
    ) -> Self {
        Self {
            object_kind,
            owner,
            dacl,
            owner_access,
            unexpected_trustee_access,
        }
    }
}

/// Opaque proof that one Windows runtime artifact met the complete owner-only
/// ACL contract. There is intentionally no public unchecked constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedWindowsOwnerAclV1(());

/// Closed failures for Windows owner-only ACL admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsOwnerAclValidationError {
    NativeEvidenceUnavailable,
    ReparsePoint,
    OwnerMismatch,
    MissingProtectedDacl,
    MissingOwnerFullControl,
    InheritedAccess,
    UnexpectedTrusteeAccess,
}

impl std::fmt::Display for WindowsOwnerAclValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NativeEvidenceUnavailable => "windows_owner_acl_evidence_unavailable",
            Self::ReparsePoint => "windows_owner_acl_reparse_point",
            Self::OwnerMismatch => "windows_owner_acl_owner_mismatch",
            Self::MissingProtectedDacl => "windows_owner_acl_dacl_unprotected",
            Self::MissingOwnerFullControl => "windows_owner_acl_owner_control_missing",
            Self::InheritedAccess => "windows_owner_acl_inherited_access",
            Self::UnexpectedTrusteeAccess => "windows_owner_acl_unexpected_trustee",
        })
    }
}

impl std::error::Error for WindowsOwnerAclValidationError {}

/// Validates the complete native Windows owner-only ACL result. Missing native
/// evidence is a typed denial; it never defaults to a permissive result.
///
/// # Errors
///
/// Returns the first closed ACL mismatch or `NativeEvidenceUnavailable`.
pub const fn validate_windows_owner_acl(
    probe: Option<WindowsOwnerAclProbeV1>,
) -> Result<ValidatedWindowsOwnerAclV1, WindowsOwnerAclValidationError> {
    let Some(probe) = probe else {
        return Err(WindowsOwnerAclValidationError::NativeEvidenceUnavailable);
    };
    if matches!(probe.object_kind, WindowsAclObjectKind::ReparsePoint) {
        return Err(WindowsOwnerAclValidationError::ReparsePoint);
    }
    if matches!(probe.owner, WindowsAclOwner::OtherPrincipal) {
        return Err(WindowsOwnerAclValidationError::OwnerMismatch);
    }
    match probe.dacl {
        WindowsDaclShape::ProtectedExplicit => {}
        WindowsDaclShape::MissingOrNull => {
            return Err(WindowsOwnerAclValidationError::MissingProtectedDacl);
        }
        WindowsDaclShape::UnprotectedOrInherited => {
            return Err(WindowsOwnerAclValidationError::InheritedAccess);
        }
    }
    if matches!(probe.owner_access, WindowsOwnerAccess::Insufficient) {
        return Err(WindowsOwnerAclValidationError::MissingOwnerFullControl);
    }
    if matches!(
        probe.unexpected_trustee_access,
        WindowsUnexpectedTrusteeAccess::Present
    ) {
        return Err(WindowsOwnerAclValidationError::UnexpectedTrusteeAccess);
    }
    Ok(ValidatedWindowsOwnerAclV1(()))
}

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
