use super::{lexer, policy_composition, policy_io};

const ENROLLMENT: &str = "crates/runne-daemon/src/application/http_startup/enrollment.rs";
const COMPOSE: &str = "crates/runne-daemon/src/canonical_provider/composition/compose.rs";
const COMPOSITION_INPUT: &str = "crates/runne-daemon/src/canonical_provider/composition/input.rs";

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

#[test]
fn token_policy_allows_only_d2_provider_identity_revalidated_before_grant() {
    let validated = r#"
        async fn compose(c: DaemonCanonicalProviderComposition) {
            let DaemonCanonicalProviderComposition { provider_id, } = c;
        let provider_name = provider_id.to_string();
        let provider_id = runne_provider::ProviderId::new(&provider_name)
            .map_err(|_| DaemonError::Bootstrap("D2 provider identity invalid".into()))?;
        let spec = runne_application::provider::ProviderSecondaryProfileGrantSpec::new(
            &provider_id,
            tool_profile.profile_id(),
            provider_name.as_str(),
            tool_profile.profile_digest(),
            tool_profile.pricing_revision_digest(),
            tokens,
            micros,
        );
        }
    "#;
    assert!(
        audit(COMPOSE, validated).is_ok(),
        "{:?}",
        audit(COMPOSE, validated)
    );

    let actual =
        include_str!("../../../../runne-daemon/src/canonical_provider/composition/compose.rs");
    assert!(
        audit(COMPOSE, actual).is_ok(),
        "{:?}",
        audit(COMPOSE, actual)
    );
    let actual_input =
        include_str!("../../../../runne-daemon/src/canonical_provider/composition/input.rs");
    let input_tokens = lexer::tokenize(actual_input).unwrap();
    assert!(policy_composition::is_d2_provider_id_input(
        COMPOSITION_INPUT,
        &input_tokens
    ));

    for (path, source) in [
        (
            COMPOSITION_INPUT,
            "struct DaemonCanonicalProviderComposition { pub(crate) provider_id: String, }",
        ),
        (
            COMPOSITION_INPUT,
            "struct OtherInput { pub(crate) provider_id: Cow<'static, str>, }",
        ),
        (
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            "struct DaemonCanonicalProviderComposition { pub(crate) provider_id: Cow<'static, str>, }",
        ),
    ] {
        let tokens = lexer::tokenize(source).unwrap();
        assert!(
            !policy_composition::is_d2_provider_id_input(path, &tokens),
            "{path}: {source}"
        );
    }

    for (before, after) in [
        ("provider_id.to_string()", "error.to_string()"),
        (
            "runne_provider::ProviderId::new",
            "runne_provider::OtherId::new",
        ),
        ("&provider_id,", "&other_id,"),
        ("provider_name.as_str()", "other_name.as_str()"),
    ] {
        let changed = validated.replace(before, after);
        assert_ne!(changed, validated, "fixture did not contain {before}");
        assert!(
            audit(COMPOSE, &changed).is_err(),
            "accepted substitution: {before} -> {after}"
        );
    }
    assert!(
        audit(
            "crates/runne-daemon/src/canonical_provider/composition/other.rs",
            validated
        )
        .is_err()
    );
}
