use super::{lexer, policy_io};

const ENROLLMENT: &str = "crates/runne-daemon/src/application/http_startup/enrollment.rs";

fn audit(path: &str, source: &str) -> Result<(), String> {
    let tokens = lexer::tokenize(source)?;
    policy_io::audit_tokens(path, &tokens)
}

#[test]
fn token_policy_allows_only_the_exact_provider_enrollment_control_list() {
    assert!(audit(
        ENROLLMENT,
        "credential_enrollment_controls: Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)>",
    )
    .is_ok());

    for (path, source) in [
        (
            "crates/runne-daemon/src/application/http_startup/other.rs",
            "credential_enrollment_controls: Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)>",
        ),
        (
            ENROLLMENT,
            "other_controls: Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)>",
        ),
        (
            ENROLLMENT,
            "credential_enrollment_controls: Vec<(String, Arc<OtherControl>)>",
        ),
        (ENROLLMENT, "let value: String;"),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
}
