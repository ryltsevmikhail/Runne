//! Policy snapshot bound to exactly one successfully transitioned V3 session.
use super::DaemonProviderCredentialEnrollmentControl;
use crate::application::provider_credential_enrollment::linux_preadmission::DaemonLinuxPreadmission;
use runne_api::provider_credential_enrollment::linux_activation_policy::LinuxInstallationFacts;
use runne_api::{
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProviderCredentialEnrollmentHostError,
};

pub(super) struct SessionGate {
    session: [u8; 16],
    gate: DaemonLinuxPreadmission,
}

#[cfg(all(test, feature = "desktop-protected"))]
mod tests {
    use super::*;
    use runne_api::{
        ProviderCredentialProviderV2, provider_credential_enrollment::linux_activation_policy::*,
    };
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn managed_record_is_bound_to_the_exact_session_and_bootstrap_authority() {
        let (mut control, _) = super::super::protected_session_tests::control();
        let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
        let root = tempfile::tempdir().unwrap();
        let mut facts = LinuxInstallationFacts {
            runtime_root_digest: [1; 32],
            desktop_image_digest: [2; 32],
            writer_image_digest: [3; 32],
            daemon_image_digest: [4; 32],
            runtime_authority_id: control.runtime_authority,
            machine_id_digest: [6; 32],
        };
        assert!(
            control
                .install_linux_preadmission(&owned, root.path(), facts)
                .is_err()
        );
        std::sync::Arc::get_mut(&mut control)
            .unwrap()
            .runtime_authority = *owned.stable().authority_id();
        facts.runtime_authority_id = control.runtime_authority;
        let record = LinuxEnrollmentActivationRecord {
            provider_scope: LinuxEnrollmentScope::Catalog,
            runtime_root_digest: facts.runtime_root_digest,
            desktop_image_digest: facts.desktop_image_digest,
            writer_image_digest: facts.writer_image_digest,
            daemon_image_digest: facts.daemon_image_digest,
            runtime_authority_id: facts.runtime_authority_id,
            machine_id_digest: facts.machine_id_digest,
            approved_at_unix_millis: 1,
        };
        let path = root.path().join(ACTIVATION_RECORD_FILE);
        std::fs::write(&path, record.to_config_json()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let session = *owned.session_id();
        assert!(
            control
                .linux_preadmission_for(session, control.runtime_authority)
                .unwrap()
                .enforce(ProviderCredentialProviderV2::OpenAi)
                .is_err()
        );
        control
            .install_linux_preadmission(&owned, root.path(), facts)
            .unwrap();
        let wrong_authority = LinuxInstallationFacts {
            runtime_authority_id: [0; 16],
            ..facts
        };
        assert!(
            control
                .install_linux_preadmission(&owned, root.path(), wrong_authority)
                .is_err()
        );
        let gate = control
            .linux_preadmission_for(session, control.runtime_authority)
            .unwrap();
        let successor = [10; 16];
        control
            .rebind_idle_linux_preadmission(session, successor)
            .unwrap();
        assert!(
            control
                .linux_preadmission_for(session, control.runtime_authority)
                .unwrap()
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err(),
            "rotation must revoke the prior signed V3 session"
        );
        assert!(
            control
                .linux_preadmission_for(successor, control.runtime_authority)
                .unwrap()
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_ok(),
            "rotation must retain live approval for its exact successor"
        );
        for provider in runne_api::provider_catalog() {
            assert!(gate.enforce(provider.provider_id.parse().unwrap()).is_ok());
        }
        assert!(
            control
                .linux_preadmission_for([8; 16], control.runtime_authority)
                .unwrap()
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err()
        );
        assert!(
            control
                .linux_preadmission_for(session, [9; 16])
                .unwrap()
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err()
        );
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(
            DaemonLinuxPreadmission::from_managed(elsewhere.path(), facts)
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err()
        );
        let altered = LinuxInstallationFacts {
            daemon_image_digest: [9; 32],
            ..facts
        };
        assert!(
            DaemonLinuxPreadmission::from_managed(root.path(), altered)
                .enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            gate.enforce(ProviderCredentialProviderV2::DeepSeek)
                .is_err(),
            "removing approval must close an already retained gate"
        );
    }
}

impl DaemonProviderCredentialEnrollmentControl {
    pub(crate) fn rebind_idle_linux_preadmission(
        &self,
        old_session: [u8; 16],
        new_session: [u8; 16],
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.rebind_linux_preadmission(old_session, new_session)
    }

    pub(super) fn rebind_linux_preadmission(
        &self,
        old_session: [u8; 16],
        new_session: [u8; 16],
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if old_session == [0; 16] || new_session == [0; 16] {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let mut slot = self
            .linux_preadmission
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if let Some(bound) = slot.as_mut() {
            if bound.session != old_session {
                return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
            }
            bound.session = new_session;
        }
        Ok(())
    }

    /// Called only after the signed transition has succeeded. Facts are
    /// independently measured from its kernel peer and managed runtime root.
    pub(crate) fn install_linux_preadmission(
        &self,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        runtime_root: &std::path::Path,
        facts: LinuxInstallationFacts,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        if facts.runtime_authority_id != self.runtime_authority
            || owned.stable().authority_id() != &self.runtime_authority
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        let gate = DaemonLinuxPreadmission::from_managed(runtime_root, facts);
        let mut slot = self
            .linux_preadmission
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        *slot = Some(SessionGate {
            session: *owned.session_id(),
            gate,
        });
        Ok(())
    }

    pub(super) fn linux_preadmission_for(
        &self,
        session: [u8; 16],
        runtime_authority: [u8; 16],
    ) -> Result<DaemonLinuxPreadmission, ProviderCredentialEnrollmentHostError> {
        let slot = self
            .linux_preadmission
            .lock()
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        Ok(match slot.as_ref() {
            Some(bound)
                if bound.session == session && runtime_authority == self.runtime_authority =>
            {
                bound.gate.clone()
            }
            _ => DaemonLinuxPreadmission::disabled(),
        })
    }
}
