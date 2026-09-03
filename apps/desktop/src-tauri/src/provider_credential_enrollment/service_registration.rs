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
    pub fn open(expected_version: &str) -> Result<Self, CredentialServiceXpcError> {
        Ok(Self {
            manager: CredentialServiceRegistrationManager::new(
                env!("CARGO_PKG_VERSION"),
                expected_version,
            )?,
        })
    }

    pub fn register(&self) -> Result<(), CredentialServiceXpcError> {
        self.manager.register()
    }

    pub fn unregister(&self) -> Result<(), CredentialServiceXpcError> {
        self.manager.unregister()
    }

    pub fn disposition(&self) -> CredentialServiceRegistrationDisposition {
        project_status(self.manager.status())
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
    use super::{
        CredentialServiceRegistrationDisposition, CredentialServiceRegistrationStatus,
        project_status,
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
}
