use std::sync::Arc;

use crate::application::provider_credential_enrollment::{
    DaemonProviderCredentialEnrollmentControl, ProtectedEnrollmentSessionFacts,
};
use runne_api::ProviderCredentialEnrollmentHostError;

type Control = Arc<DaemonProviderCredentialEnrollmentControl>;

pub(crate) fn publish(
    controls: &[Control],
    facts: &ProtectedEnrollmentSessionFacts,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    for (index, control) in controls.iter().enumerate() {
        if let Err(error) = control.publish_http_facts(facts.clone()) {
            clear(&controls[..=index], facts.session);
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn clear(controls: &[Control], session: [u8; 16]) {
    for control in controls {
        control.clear_http_facts(session);
    }
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(crate) fn install_linux_preadmission(
    controls: &[Control],
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    runtime_root: &std::path::Path,
    facts: runne_api::provider_credential_enrollment::linux_activation_policy::LinuxInstallationFacts,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if controls.is_empty() {
        return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    for (index, control) in controls.iter().enumerate() {
        if let Err(error) = control.install_linux_preadmission(owned, runtime_root, facts) {
            clear_linux_preadmission(&controls[..index], *owned.session_id());
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(crate) fn clear_linux_preadmission(controls: &[Control], session: [u8; 16]) {
    for control in controls {
        control.clear_linux_preadmission(session);
    }
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(crate) fn refresh_linux_session(
    controls: &[Control],
    old_session: [u8; 16],
    new_session: [u8; 16],
    facts: &ProtectedEnrollmentSessionFacts,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if old_session != new_session {
        clear(controls, old_session);
    }
    if old_session != new_session
        && let Err(error) = rebind_linux_preadmission(controls, old_session, new_session)
    {
        clear(controls, old_session);
        clear(controls, new_session);
        clear_linux_preadmission(controls, old_session);
        clear_linux_preadmission(controls, new_session);
        return Err(error);
    }
    if let Err(error) = publish(controls, facts) {
        clear(controls, old_session);
        clear(controls, new_session);
        clear_linux_preadmission(controls, old_session);
        clear_linux_preadmission(controls, new_session);
        return Err(error);
    }
    if old_session != new_session {
        clear(controls, old_session);
        clear_linux_preadmission(controls, old_session);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(crate) fn rebind_linux_preadmission(
    controls: &[Control],
    old_session: [u8; 16],
    new_session: [u8; 16],
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    let mut rebound: Vec<&Control> = Vec::new();
    for control in controls {
        if let Err(error) = control.rebind_idle_linux_preadmission(old_session, new_session) {
            let mut rollback_failed = false;
            for previous in rebound.into_iter().rev() {
                rollback_failed |= previous
                    .rebind_idle_linux_preadmission(new_session, old_session)
                    .is_err();
            }
            return Err(if rollback_failed {
                ProviderCredentialEnrollmentHostError::InvariantViolation
            } else {
                error
            });
        }
        rebound.push(control);
    }
    if controls.is_empty() {
        return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn publish_v2(
    controls: &[Control],
    owned: &runne_api::ProtectedOwnedLaunchV2,
    installation: [u8; 32],
    release: [u8; 32],
    peer: [u8; 32],
    supervisor: u64,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    for (index, control) in controls.iter().enumerate() {
        if let Err(error) =
            control.publish_verified_v2_status(owned, installation, release, peer, supervisor)
        {
            clear(&controls[..=index], *owned.session_id());
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::provider_credential_enrollment::{
        test_control, test_http_status_facts_available,
    };

    #[test]
    fn publication_and_teardown_use_same_verified_session_for_each_realm() {
        let (primary, _) = test_control();
        let (background, _) = test_control();
        let facts = ProtectedEnrollmentSessionFacts::for_test();
        let controls = [primary.clone(), background.clone()];

        publish(&controls, &facts).expect("same verified facts published");
        assert!(test_http_status_facts_available(&primary, facts.session));
        assert!(test_http_status_facts_available(&background, facts.session));

        clear(&controls, facts.session);
        assert!(!test_http_status_facts_available(&primary, facts.session));
        assert!(!test_http_status_facts_available(
            &background,
            facts.session
        ));

        let prior_session = facts.session;
        let mut renewed = facts;
        renewed.session = [12; 16];
        publish(&controls, &renewed).expect("renewed facts published");
        assert!(!test_http_status_facts_available(&primary, prior_session));
        assert!(!test_http_status_facts_available(
            &background,
            prior_session
        ));
        assert!(test_http_status_facts_available(&primary, renewed.session));
        assert!(test_http_status_facts_available(
            &background,
            renewed.session
        ));
        clear(&controls, prior_session);
        assert!(test_http_status_facts_available(&primary, renewed.session));
        assert!(test_http_status_facts_available(
            &background,
            renewed.session
        ));
        clear(&controls, renewed.session);
        assert!(!test_http_status_facts_available(&primary, renewed.session));
        assert!(!test_http_status_facts_available(
            &background,
            renewed.session
        ));
    }

    #[test]
    fn failed_second_realm_publication_clears_the_first_realm() {
        let (primary, _) = test_control();
        let (background, _) = test_control();
        let facts = ProtectedEnrollmentSessionFacts::for_test();
        background.poison_http_facts_for_test();

        assert!(publish(&[primary.clone(), background], &facts).is_err());
        assert!(!test_http_status_facts_available(&primary, facts.session));
    }
}

#[cfg(all(test, target_os = "linux", feature = "desktop-protected"))]
#[path = "enrollment_control_fanout/linux_gate_tests.rs"]
mod linux_gate_tests;
