use runne_macos_xpc::{
    CredentialServiceRegistrationManager, CredentialServiceRegistrationStatus,
    CredentialServiceXpcError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceRegistrationDisposition {
    NotRegistered,
    Enabled,
    ApprovalRequired,
    NotFound,
    Unavailable,
}

pub struct CredentialServiceRegistration {
    manager: CredentialServiceRegistrationManager,
}

impl CredentialServiceRegistration {
    /// Opens the native registration manager for one exact service version.
    ///
    /// # Errors
    ///
    /// Returns a closed XPC error when the service contract is unavailable.
    pub fn open(expected_version: &str) -> Result<Self, CredentialServiceXpcError> {
        Ok(Self {
            manager: CredentialServiceRegistrationManager::new(
                env!("CARGO_PKG_VERSION"),
                expected_version,
            )?,
        })
    }

    /// Registers the service with the native service manager.
    ///
    /// # Errors
    ///
    /// Returns a closed XPC error when registration is rejected.
    pub fn register(&self) -> Result<(), CredentialServiceXpcError> {
        self.manager.register()
    }

    /// Removes the service registration from the native service manager.
    ///
    /// # Errors
    ///
    /// Returns a closed XPC error when removal cannot be completed.
    pub fn unregister(&self) -> Result<(), CredentialServiceXpcError> {
        self.manager.unregister()
    }

    #[must_use]
    pub fn disposition(&self) -> CredentialServiceRegistrationDisposition {
        project_status(self.manager.status())
    }
}

/// Closed reasons the packaged credential service cannot serve enrollments yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceGateError {
    /// macOS holds the registration until the user approves it in Login Items.
    ApprovalRequired,
    /// The app bundle does not carry the credentialed LaunchAgent.
    NotFound,
    /// Service Management reported any other non-serving state.
    Unavailable,
}

impl CredentialServiceGateError {
    /// Stable IPC code surfaced to the renderer.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ApprovalRequired => "provider_credential_service_approval_required",
            Self::NotFound => "provider_credential_service_not_found",
            Self::Unavailable => "provider_credential_service_unavailable",
        }
    }
}

/// Ensures the bundled credential service is registered for this login session.
///
/// Enrollment and status reads require the LaunchAgent's Mach services; without
/// the registration every XPC lookup fails closed into an opaque status error.
///
/// # Errors
///
/// Returns a closed gate error when the service cannot be opened, is missing
/// from the bundle, is withheld for approval, or registration is rejected.
pub fn ensure_registered() -> Result<(), CredentialServiceGateError> {
    let registration = CredentialServiceRegistration::open(env!("CARGO_PKG_VERSION"))
        .map_err(|_| CredentialServiceGateError::Unavailable)?;
    gate_disposition(registration.disposition(), || registration.register())
}

fn gate_disposition(
    disposition: CredentialServiceRegistrationDisposition,
    register: impl FnOnce() -> Result<(), CredentialServiceXpcError>,
) -> Result<(), CredentialServiceGateError> {
    match disposition {
        CredentialServiceRegistrationDisposition::Enabled => Ok(()),
        // A bundled-but-never-installed agent reports `NotFound` until Service
        // Management adopts it, so both states get one registration attempt.
        CredentialServiceRegistrationDisposition::NotRegistered
        | CredentialServiceRegistrationDisposition::NotFound => match register() {
            Ok(()) => Ok(()),
            Err(_) => Err(match disposition {
                CredentialServiceRegistrationDisposition::NotFound => {
                    CredentialServiceGateError::NotFound
                }
                _ => CredentialServiceGateError::Unavailable,
            }),
        },
        CredentialServiceRegistrationDisposition::ApprovalRequired => {
            Err(CredentialServiceGateError::ApprovalRequired)
        }
        CredentialServiceRegistrationDisposition::Unavailable => {
            Err(CredentialServiceGateError::Unavailable)
        }
    }
}

const fn project_status(
    status: CredentialServiceRegistrationStatus,
) -> CredentialServiceRegistrationDisposition {
    match status {
        CredentialServiceRegistrationStatus::NotRegistered => {
            CredentialServiceRegistrationDisposition::NotRegistered
        }
        CredentialServiceRegistrationStatus::Enabled => {
            CredentialServiceRegistrationDisposition::Enabled
        }
        CredentialServiceRegistrationStatus::RequiresApproval => {
            CredentialServiceRegistrationDisposition::ApprovalRequired
        }
        CredentialServiceRegistrationStatus::NotFound => {
            CredentialServiceRegistrationDisposition::NotFound
        }
        CredentialServiceRegistrationStatus::Unavailable => {
            CredentialServiceRegistrationDisposition::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use runne_macos_xpc::CredentialServiceXpcError;

    use super::{
        CredentialServiceGateError, CredentialServiceRegistrationDisposition,
        CredentialServiceRegistrationStatus, gate_disposition, project_status,
    };

    #[test]
    fn every_native_status_has_a_closed_desktop_projection() {
        let cases = [
            (
                CredentialServiceRegistrationStatus::NotRegistered,
                CredentialServiceRegistrationDisposition::NotRegistered,
            ),
            (
                CredentialServiceRegistrationStatus::Enabled,
                CredentialServiceRegistrationDisposition::Enabled,
            ),
            (
                CredentialServiceRegistrationStatus::RequiresApproval,
                CredentialServiceRegistrationDisposition::ApprovalRequired,
            ),
            (
                CredentialServiceRegistrationStatus::NotFound,
                CredentialServiceRegistrationDisposition::NotFound,
            ),
            (
                CredentialServiceRegistrationStatus::Unavailable,
                CredentialServiceRegistrationDisposition::Unavailable,
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(project_status(status), expected);
        }
    }

    #[test]
    fn enabled_service_needs_no_registration() {
        let mut registered = false;
        let outcome = gate_disposition(
            CredentialServiceRegistrationDisposition::Enabled,
            || {
                registered = true;
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(()));
        assert!(!registered, "enabled service must not be registered twice");
    }

    #[test]
    fn unregistered_service_is_registered_before_serving() {
        let mut registered = false;
        let outcome = gate_disposition(
            CredentialServiceRegistrationDisposition::NotRegistered,
            || {
                registered = true;
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(()));
        assert!(registered, "missing registration must be created");
    }

    #[test]
    fn rejected_or_withheld_registration_fails_closed() {
        let cases = [
            (
                CredentialServiceRegistrationDisposition::ApprovalRequired,
                CredentialServiceGateError::ApprovalRequired,
            ),
            (
                CredentialServiceRegistrationDisposition::Unavailable,
                CredentialServiceGateError::Unavailable,
            ),
        ];
        for (disposition, expected) in cases {
            let outcome = gate_disposition(disposition, || Ok(()));
            assert_eq!(outcome, Err(expected));
        }
        let not_found = gate_disposition(
            CredentialServiceRegistrationDisposition::NotFound,
            || Err(CredentialServiceXpcError::NotFound),
        );
        assert_eq!(not_found, Err(CredentialServiceGateError::NotFound));
        let rejected = gate_disposition(
            CredentialServiceRegistrationDisposition::NotRegistered,
            || Err(CredentialServiceXpcError::Rejected),
        );
        assert_eq!(
            rejected,
            Err(CredentialServiceGateError::Unavailable)
        );
    }

    #[test]
    fn a_never_installed_agent_is_adopted_on_the_first_attempt() {
        let mut registered = false;
        let outcome = gate_disposition(
            CredentialServiceRegistrationDisposition::NotFound,
            || {
                registered = true;
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(()));
        assert!(registered, "NotFound must still be offered to Service Management");
    }

    #[test]
    fn gate_errors_have_stable_ipc_codes() {
        assert_eq!(
            CredentialServiceGateError::ApprovalRequired.code(),
            "provider_credential_service_approval_required"
        );
        assert_eq!(
            CredentialServiceGateError::NotFound.code(),
            "provider_credential_service_not_found"
        );
        assert_eq!(
            CredentialServiceGateError::Unavailable.code(),
            "provider_credential_service_unavailable"
        );
    }
}
