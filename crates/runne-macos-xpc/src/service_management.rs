use crate::CredentialServiceXpcError;

pub const LAUNCH_AGENT_PLIST: &str = "com.runne.credential-service.plist";

/// Safe projection of every current `SMAppServiceStatus` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceRegistrationStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    Unavailable,
}

pub const fn map_status_code(code: isize) -> CredentialServiceRegistrationStatus {
    match code {
        0 => CredentialServiceRegistrationStatus::NotRegistered,
        1 => CredentialServiceRegistrationStatus::Enabled,
        2 => CredentialServiceRegistrationStatus::RequiresApproval,
        3 => CredentialServiceRegistrationStatus::NotFound,
        _ => CredentialServiceRegistrationStatus::Unavailable,
    }
}

pub fn validate_registration_version(
    installed: &str,
    expected: &str,
) -> Result<(), CredentialServiceXpcError> {
    if installed.is_empty() || expected.is_empty() || installed != expected {
        return Err(CredentialServiceXpcError::VersionSkew);
    }
    Ok(())
}

pub const fn operation_error(
    status: CredentialServiceRegistrationStatus,
) -> CredentialServiceXpcError {
    match status {
        CredentialServiceRegistrationStatus::RequiresApproval => {
            CredentialServiceXpcError::ApprovalRequired
        }
        CredentialServiceRegistrationStatus::NotFound => CredentialServiceXpcError::NotFound,
        CredentialServiceRegistrationStatus::NotRegistered
        | CredentialServiceRegistrationStatus::Enabled
        | CredentialServiceRegistrationStatus::Unavailable => {
            CredentialServiceXpcError::Unavailable
        }
    }
}

/// Safe owner of the exact bundled `LaunchAgent` registration.
pub struct CredentialServiceRegistrationManager {
    expected_version: String,
    #[cfg(target_os = "macos")]
    native: objc2::rc::Retained<objc2_service_management::SMAppService>,
}

impl CredentialServiceRegistrationManager {
    /// Opens the exact packaged `LaunchAgent` only for the measured version.
    ///
    /// # Errors
    ///
    /// Rejects version skew and returns typed unsupported outside macOS.
    pub fn new(
        installed_version: &str,
        expected_version: &str,
    ) -> Result<Self, CredentialServiceXpcError> {
        validate_registration_version(installed_version, expected_version)?;
        #[cfg(target_os = "macos")]
        {
            use objc2_foundation::NSString;
            let plist = NSString::from_str(LAUNCH_AGENT_PLIST);
            // SAFETY: the fixed plist name is a valid bundled LaunchAgent lookup.
            let native = unsafe {
                objc2_service_management::SMAppService::agentServiceWithPlistName(&plist)
            };
            Ok(Self {
                expected_version: expected_version.to_owned(),
                native,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = expected_version;
            Err(CredentialServiceXpcError::Unsupported)
        }
    }

    /// Registers the measured bundled `LaunchAgent`.
    ///
    /// # Errors
    ///
    /// Maps native failures to closed status-based dispositions.
    pub fn register(&self) -> Result<(), CredentialServiceXpcError> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` is the retained fixed LaunchAgent service.
            unsafe { self.native.registerAndReturnError() }
                .map_err(|_| operation_error(self.status()))
        }
        #[cfg(not(target_os = "macos"))]
        Err(CredentialServiceXpcError::Unsupported)
    }

    /// Unregisters only the exact measured bundled `LaunchAgent`.
    ///
    /// # Errors
    ///
    /// Maps native failures to closed status-based dispositions.
    pub fn unregister(&self) -> Result<(), CredentialServiceXpcError> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` is the retained fixed LaunchAgent service.
            unsafe { self.native.unregisterAndReturnError() }
                .map_err(|_| operation_error(self.status()))
        }
        #[cfg(not(target_os = "macos"))]
        Err(CredentialServiceXpcError::Unsupported)
    }

    #[must_use]
    pub fn status(&self) -> CredentialServiceRegistrationStatus {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: reading status has no out parameters and `native` is retained.
            map_status_code(unsafe { self.native.status() }.0)
        }
        #[cfg(not(target_os = "macos"))]
        CredentialServiceRegistrationStatus::Unavailable
    }

    #[must_use]
    pub fn expected_version(&self) -> &str {
        &self.expected_version
    }
}
