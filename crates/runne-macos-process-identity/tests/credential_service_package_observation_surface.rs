#![cfg(target_os = "macos")]

#[path = "credential_service_package_observation_surface/guard.rs"]
mod guard;

use guard::{count_credential_service_calls, is_workspace_production_source, production_text};
use runne_api::VerifiedSignedInstalledReleaseV2;
use runne_macos_process_identity::{
    MacOsCredentialServicePackageObservationError,
    MacOsPendingCredentialServicePackageObservationV1, MacOsVerifiedCredentialServicePackageV1,
};
use std::path::PathBuf;

#[test]
fn credential_service_observation_pure_public_contract_is_closed_and_exact() {
    let capture: fn() -> Result<
        MacOsPendingCredentialServicePackageObservationV1,
        MacOsCredentialServicePackageObservationError,
    > = MacOsPendingCredentialServicePackageObservationV1::capture_current;
    let verify: fn(
        MacOsPendingCredentialServicePackageObservationV1,
        &VerifiedSignedInstalledReleaseV2,
    ) -> Result<
        MacOsVerifiedCredentialServicePackageV1,
        MacOsCredentialServicePackageObservationError,
    > = MacOsPendingCredentialServicePackageObservationV1::verify_exact;
    let _ = (capture, verify);

    assert_eq!(
        format!(
            "{:?}",
            MacOsCredentialServicePackageObservationError::Rejected
        ),
        "Rejected"
    );
    assert_eq!(
        format!(
            "{:?}",
            MacOsCredentialServicePackageObservationError::Unavailable
        ),
        "Unavailable"
    );
}

#[test]
fn credential_service_observation_pure_surface_has_no_authority_or_fact_escape() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let facade = production_text(&root.join("src/credential_service_package_observation.rs"));
    for forbidden in [
        "pub fn path",
        "pub fn pid",
        "pub fn fd",
        "pub fn root",
        "pub fn digest",
        "pub fn identity",
        "pub fn fault",
        "pub fn ack",
        "pub fn callback",
        "into_authority",
        "verify_exact_service_fault_borrowed",
    ] {
        assert!(
            !facade.contains(forbidden),
            "forbidden public surface: {forbidden}"
        );
    }
    assert_eq!(facade.matches("pub fn capture_current(").count(), 1);
    assert_eq!(facade.matches("pub fn verify_exact(").count(), 1);
    let workspace = root.parent().unwrap().parent().unwrap();
    guard::assert_workspace_has_no_credential_service_calls(
        workspace,
        &root.join("src/credential_service_package_observation.rs"),
    );
}

#[test]
fn credential_service_observation_pure_workspace_guard_does_not_trust_test_fixture_path_names() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let facade = root.join("src/credential_service_package_observation.rs");
    assert!(is_workspace_production_source(&facade, &facade));
    for source in [
        root.join("test_fixture/main.rs"),
        root.join("src/tests.rs"),
        root.join("src/package/feature_tests.rs"),
        root.join("src/tests/support.rs"),
        root.join("src/package/release_fixture.rs"),
        root.join("tests/external.rs"),
    ] {
        assert!(is_workspace_production_source(&source, &facade));
    }
    assert!(is_workspace_production_source(
        &root.join("src/package/production.rs"),
        &facade
    ));
    assert_eq!(
        count_credential_service_calls(
            "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1;",
        ),
        0
    );
    assert_eq!(
        count_credential_service_calls(
            "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as PendingObservation;\nfn production() { let capture = PendingObservation::capture_current(); }",
        ),
        1
    );
    assert_eq!(
        count_credential_service_calls(
            "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as PendingObservation;\nfn production(pending: PendingObservation, release: &Release) { PendingObservation::verify_exact(pending, release); }",
        ),
        1
    );
    assert_eq!(
        count_credential_service_calls(
            "mod reexport { pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Reexported; } use crate::reexport::Reexported as Pending; fn call() { Pending::capture_current(); }",
        ),
        1
    );
}

#[test]
fn credential_service_observation_pure_ast_guard_ignores_comments_and_cfg_test() {
    assert_eq!(
        count_credential_service_calls(
            r"
            // use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
            // Pending::capture_current();
            struct Profile;
            mod subject { pub fn capture_current(_: super::Profile) {} }
            fn unrelated(profile: Profile) { subject::capture_current(profile); }
            ",
        ),
        0
    );
    assert_eq!(
        count_credential_service_calls(
            r"
            #[cfg(test)]
            mod tests {
                use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
                fn hidden() { let _ = Pending::capture_current(); }
            }
            #[test]
            fn hidden_test() {
                use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
                let _ = Pending::verify_exact(pending, &release);
            }
            ",
        ),
        0
    );
}

#[test]
fn credential_service_observation_pure_ast_guard_keeps_production_cfg_and_target_receiver_only() {
    let production_cfg = r#"
        use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
        #[cfg(not(test))]
        fn production() { Pending::capture_current(); }
        #[cfg(any(test, feature = "production"))]
        fn also_production() { Pending::capture_current(); }
        #[cfg_attr(test, allow(dead_code))]
        fn cfg_attr_production() { Pending::capture_current(); }
        #[cfg(all(test, feature = "test-only"))]
        fn test_only() { Pending::capture_current(); }
    "#;
    assert_eq!(count_credential_service_calls(production_cfg), 3);
    assert_eq!(
        count_credential_service_calls(
            r"
            use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending;
            fn calls(pending: Pending, unrelated: Other) {
                pending.verify_exact(release);
                unrelated.verify_exact(release);
            }
            ",
        ),
        1
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the source-order guard intentionally keeps the final gate checklist together"
)]
fn credential_service_observation_pure_final_gate_keeps_all_required_observations() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let facade = production_text(&root.join("src/credential_service_package_observation.rs"));
    let process = production_text(
        &root.join("src/credential_service_package_observation/current_process.rs"),
    );
    let package =
        production_text(&root.join("src/credential_service_package_observation/package.rs"));
    let entries = production_text(
        &root.join("src/credential_service_package_observation/package/entries.rs"),
    );
    for forbidden in [
        "current_exe(",
        "read_to_end(",
        "runne_platform",
        "runne_daemon",
        "runne_provider",
        "ACK",
    ] {
        assert!(
            !format!("{facade}\n{process}\n{package}").contains(forbidden),
            "forbidden native primitive: {forbidden}"
        );
    }
    let captured_identity = facade
        .find("let (pid, start) = observe_current_identity()?;")
        .unwrap();
    let captured_code = facade
        .find("let code = NativeCodeObservation::capture_self()")
        .unwrap();
    let application = facade
        .find("let application = application_from_service")
        .unwrap();
    let package_capture = facade
        .find("let package = ServicePackage::capture")
        .unwrap();
    let process_capture = facade
        .find("CurrentServiceProcess::capture(&package, code, pid, start)")
        .unwrap();
    assert!(
        captured_identity < captured_code
            && captured_code < application
            && application < package_capture
            && package_capture < process_capture
    );
    let first_package = facade.find("self.package.revalidate()?").unwrap();
    let static_check = facade
        .find("match_service_static_identities(tuple")
        .unwrap();
    let fresh_process = facade.find("self.process.revalidate").unwrap();
    let final_package = facade.rfind("self.package.revalidate()?").unwrap();
    assert!(
        first_package < static_check
            && static_check < fresh_process
            && fresh_process < final_package
    );
    for required in [
        "NativeCodeObservation::capture_self",
        "observe_start",
        "observe_executable_mapping",
        "matches_fresh",
    ] {
        assert!(
            process.contains(required),
            "missing current-service race check: {required}"
        );
    }
    let capture_start = process.find("start: MacOsProcessStartIdentity").unwrap();
    let capture_validation = process.find("code.revalidate().map_err(map)?;").unwrap();
    let capture_vnode = process.find(".observe_executable_mapping(pid)").unwrap();
    let capture_end = process.find("(observe_start(pid)? == start)").unwrap();
    assert!(
        capture_start < capture_validation
            && capture_validation < capture_vnode
            && capture_vnode < capture_end
    );
    let final_start = process
        .find("observe_start(self.pid)? == self.start")
        .unwrap();
    let final_revalidation = &process[final_start..];
    let final_code = final_revalidation
        .find("NativeCodeObservation::capture_self")
        .unwrap();
    let final_vnode = final_revalidation
        .find(".observe_executable_mapping(self.pid)")
        .unwrap();
    let final_end = final_revalidation
        .rfind("observe_start(self.pid)? == self.start")
        .unwrap();
    assert!(final_code < final_vnode && final_vnode < final_end);
    for required in [
        "ENTRIES",
        "candidate_binding",
        "release_digests",
        "same_vnode",
        "MAX_AGGREGATE_BYTES",
    ] {
        assert!(
            format!("{package}\n{entries}").contains(required),
            "missing retained-package requirement: {required}"
        );
    }
}
