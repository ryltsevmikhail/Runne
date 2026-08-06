use gocode_security::process_contract::ExplicitEnvironmentV1;

use super::support::{MARKER, intent, text};

#[test]
fn shell_like_argv_is_literal_and_debug_is_redacted() {
    let value = text(MARKER);
    let argv = gocode_security::process_contract::BoundedArgvV1::new(
        vec![value.clone()],
        super::support::bounds(),
    )
    .expect("marker fits bounds");
    let first = intent(vec![value.clone()]);
    let second = intent(vec![value]);

    assert_eq!(first.digest(), second.digest());
    for output in [
        format!("{:?}", text(MARKER)),
        format!("{argv:?}"),
        format!("{first:?}"),
    ] {
        assert!(!output.contains(MARKER));
    }
}

#[test]
fn environment_is_empty_by_default_without_ambient_lookup() {
    assert!(ExplicitEnvironmentV1::empty().is_empty());
    let input_contract = include_str!("../../src/process_contract/intent/input.rs");

    for ambient_lookup in ["std::env", "var_os", "vars_os"] {
        assert!(!input_contract.contains(ambient_lookup));
    }
}

#[test]
fn facade_does_not_reexport_authority_constructors() {
    let facade = include_str!("../../src/process_contract.rs");
    let authorization_reexport = facade
        .split_once("pub use authorization::")
        .and_then(|(_, remainder)| remainder.split_once(';'))
        .map(|(reexport, _)| reexport)
        .expect("facade reexports only named authorization contracts");

    for private_constructor in [
        "mint",
        "approve",
        "validate_authorization",
        "AuthorizationReplayGuard",
    ] {
        assert!(
            !authorization_reexport.contains(private_constructor),
            "public facade must not reexport {private_constructor}"
        );
    }
}
