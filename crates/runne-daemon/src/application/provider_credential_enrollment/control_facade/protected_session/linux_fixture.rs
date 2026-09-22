//! Explicit fixture installation; never compiled into production.
use super::DaemonProtectedCredentialEnrollmentSession;
use crate::application::provider_credential_enrollment::linux_preadmission::DaemonLinuxPreadmission;
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    LinuxEnrollmentActivationRecord, LinuxEnrollmentScope, LinuxInstallationFacts,
};

impl DaemonProtectedCredentialEnrollmentSession {
    pub(crate) fn activate_linux_catalog_fixture(&mut self) {
        let facts = LinuxInstallationFacts {
            runtime_root_digest: [1; 32],
            desktop_image_digest: [2; 32],
            writer_image_digest: [3; 32],
            daemon_image_digest: [4; 32],
            runtime_authority_id: [5; 16],
            machine_id_digest: [6; 32],
        };
        let record = LinuxEnrollmentActivationRecord {
            provider_scope: LinuxEnrollmentScope::Catalog,
            runtime_root_digest: facts.runtime_root_digest,
            desktop_image_digest: facts.desktop_image_digest,
            writer_image_digest: facts.writer_image_digest,
            daemon_image_digest: facts.daemon_image_digest,
            runtime_authority_id: facts.runtime_authority_id,
            machine_id_digest: facts.machine_id_digest,
            approved_at_unix_millis: 1_700_000_000_000,
        };
        let record =
            LinuxEnrollmentActivationRecord::from_config_json(&record.to_config_json()).unwrap();
        self.admissions
            .set_linux_gate_for_test(DaemonLinuxPreadmission::from_parts(Some(record), facts));
    }
}
