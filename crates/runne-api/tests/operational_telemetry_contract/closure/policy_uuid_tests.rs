use super::{lexer, policy_io};

const AUTOMATIC_TASKRUNS: &str =
    "crates/runne-daemon/src/application/http_startup/automatic_taskruns.rs";

fn audit(path: &str, source: &str) -> Result<(), String> {
    let tokens = lexer::tokenize(source)?;
    policy_io::audit_tokens(path, &tokens)
}

#[test]
fn token_policy_allows_only_exact_authority_uuid_formatting() {
    assert!(
        audit(
            "crates/runne-daemon/src/application/http_startup.rs",
            "DaemonError::Config(error.to_string());",
        )
        .is_ok()
    );

    assert!(
        audit(
            AUTOMATIC_TASKRUNS,
            "let id = uuid::Uuid::from_bytes(authority_id).to_string();",
        )
        .is_ok()
    );

    for (path, source) in [
        (
            "crates/runne-daemon/src/application/http_startup/other.rs",
            "let id = uuid::Uuid::from_bytes(authority_id).to_string();",
        ),
        (
            AUTOMATIC_TASKRUNS,
            "let id = uuid::Uuid::from_bytes(other_id).to_string();",
        ),
        (
            AUTOMATIC_TASKRUNS,
            "let id = uuid::Uuid::from_bytes(authority_id, other_id).to_string();",
        ),
        (
            AUTOMATIC_TASKRUNS,
            "let id = arbitrary::Uuid::from_bytes(authority_id).to_string();",
        ),
        (AUTOMATIC_TASKRUNS, "let id = error.to_string();"),
    ] {
        assert!(audit(path, source).is_err(), "{path}: {source}");
    }
}
