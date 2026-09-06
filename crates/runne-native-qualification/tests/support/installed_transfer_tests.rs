use super::installed_surface_audit::audit_sources;
use super::installed_surface_daemon::{SESSION_SOURCE, TRANSFER_SOURCE};

const SESSION: &str = "pub(crate) struct DaemonProtectedCredentialEnrollmentSession {
#[cfg(all(target_os = \"macos\", feature = \"desktop-protected\"))]
qualification: Option<crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission>
}";
const TRANSFER: &str = "impl DaemonProtectedCredentialEnrollmentSession {
pub(crate) fn retain_qualification(mut self, qualification: VerifiedQualificationAdmission) -> Result<Self, ProviderCredentialEnrollmentHostError> { todo!() }
}";

#[test]
fn only_exact_private_session_ownership_transfer_is_allowed() {
    assert!(
        audit_sources(&[(SESSION_SOURCE, SESSION), (TRANSFER_SOURCE, TRANSFER)])
            .violations
            .is_empty()
    );
    for mutation in [
        SESSION.replace("pub(crate) struct", "pub struct"),
        SESSION.replace("qualification: Option", "pub(crate) qualification: Option"),
        SESSION.replace("qualification: Option", "pub qualification: Option"),
        SESSION.replace("pub(crate) struct", "#[derive(Clone)] pub(crate) struct"),
        SESSION.replace("pub(crate) struct", "#[derive(Debug)] pub(crate) struct"),
        SESSION.replace("pub(crate) struct", "#[derive(Default)] pub(crate) struct"),
        SESSION.replace("Option<crate", "Vec<crate"),
        SESSION.replace("qualification: Option", "other: Option"),
        SESSION.replace("DaemonProtectedCredentialEnrollmentSession", "OtherSession"),
        format!("{SESSION}\nstruct Wrapper(VerifiedQualificationAdmission);"),
        format!(
            "{SESSION}\nimpl DaemonProtectedCredentialEnrollmentSession {{ fn take(&mut self) -> Option<VerifiedQualificationAdmission> {{ todo!() }} }}"
        ),
    ] {
        assert!(
            !audit_sources(&[(SESSION_SOURCE, &mutation)])
                .violations
                .is_empty(),
            "session ownership escaped"
        );
    }
    for mutation in [
        TRANSFER.replace("pub(crate) fn", "pub fn"),
        TRANSFER.replace("mut self", "&mut self"),
        TRANSFER.replace("qualification: Verified", "qualification: &Verified"),
        TRANSFER.replace(
            "qualification: VerifiedQualificationAdmission",
            "qualification: Option<VerifiedQualificationAdmission>",
        ),
        TRANSFER.replace("Result<Self,", "Result<VerifiedQualificationAdmission,"),
        TRANSFER.replace("DaemonProtectedCredentialEnrollmentSession", "OtherSession"),
        TRANSFER.replace("retain_qualification", "get_qualification"),
        TRANSFER.replace(
            "pub(crate) fn",
            "#[cfg_attr(test, allow(dead_code))] pub(crate) fn",
        ),
        format!("{TRANSFER}\ntype Alias = VerifiedQualificationAdmission;"),
    ] {
        assert!(
            !audit_sources(&[(TRANSFER_SOURCE, &mutation)])
                .violations
                .is_empty(),
            "transfer ownership escaped"
        );
    }
    assert!(
        !audit_sources(&[("other.rs", SESSION), ("other.rs", TRANSFER)])
            .violations
            .is_empty()
    );
}
