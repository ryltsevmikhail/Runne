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

    #[test]
    fn windows_owner_acl_contract_accepts_only_exact_native_evidence() {
        let exact = WindowsOwnerAclProbeV1::new(
            WindowsAclObjectKind::DirectFile,
            WindowsAclOwner::CurrentPrincipal,
            WindowsDaclShape::ProtectedExplicit,
            WindowsOwnerAccess::FullControl,
            WindowsUnexpectedTrusteeAccess::Absent,
        );
        assert_eq!(
            validate_windows_owner_acl(Some(exact)),
            Ok(ValidatedWindowsOwnerAclV1(()))
        );

        for (probe, expected) in [
            (
                None,
                WindowsOwnerAclValidationError::NativeEvidenceUnavailable,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::ReparsePoint,
                    WindowsAclOwner::CurrentPrincipal,
                    WindowsDaclShape::ProtectedExplicit,
                    WindowsOwnerAccess::FullControl,
                    WindowsUnexpectedTrusteeAccess::Absent,
                )),
                WindowsOwnerAclValidationError::ReparsePoint,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::DirectFile,
                    WindowsAclOwner::OtherPrincipal,
                    WindowsDaclShape::ProtectedExplicit,
                    WindowsOwnerAccess::FullControl,
                    WindowsUnexpectedTrusteeAccess::Absent,
                )),
                WindowsOwnerAclValidationError::OwnerMismatch,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::DirectFile,
                    WindowsAclOwner::CurrentPrincipal,
                    WindowsDaclShape::MissingOrNull,
                    WindowsOwnerAccess::FullControl,
                    WindowsUnexpectedTrusteeAccess::Absent,
                )),
                WindowsOwnerAclValidationError::MissingProtectedDacl,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::DirectFile,
                    WindowsAclOwner::CurrentPrincipal,
                    WindowsDaclShape::UnprotectedOrInherited,
                    WindowsOwnerAccess::FullControl,
                    WindowsUnexpectedTrusteeAccess::Absent,
                )),
                WindowsOwnerAclValidationError::InheritedAccess,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::DirectFile,
                    WindowsAclOwner::CurrentPrincipal,
                    WindowsDaclShape::ProtectedExplicit,
                    WindowsOwnerAccess::Insufficient,
                    WindowsUnexpectedTrusteeAccess::Absent,
                )),
                WindowsOwnerAclValidationError::MissingOwnerFullControl,
            ),
            (
                Some(WindowsOwnerAclProbeV1::new(
                    WindowsAclObjectKind::DirectFile,
                    WindowsAclOwner::CurrentPrincipal,
                    WindowsDaclShape::ProtectedExplicit,
                    WindowsOwnerAccess::FullControl,
                    WindowsUnexpectedTrusteeAccess::Present,
                )),
                WindowsOwnerAclValidationError::UnexpectedTrusteeAccess,
            ),
        ] {
            assert_eq!(validate_windows_owner_acl(probe), Err(expected));
        }
    }

    #[test]
    fn windows_owner_acl_errors_are_path_and_sid_free() {
        for error in [
            WindowsOwnerAclValidationError::NativeEvidenceUnavailable,
            WindowsOwnerAclValidationError::ReparsePoint,
            WindowsOwnerAclValidationError::OwnerMismatch,
            WindowsOwnerAclValidationError::MissingProtectedDacl,
            WindowsOwnerAclValidationError::MissingOwnerFullControl,
            WindowsOwnerAclValidationError::InheritedAccess,
            WindowsOwnerAclValidationError::UnexpectedTrusteeAccess,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains('\\'));
            assert!(!rendered.contains("S-1-"));
            assert!(!rendered.contains("Users"));
        }
    }
}
