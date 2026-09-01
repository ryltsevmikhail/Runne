#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};

#[test]
fn pending_surface_is_opaque_move_only_and_has_no_authority_transition() {
    let facade = production_text(&manifest().join("src/packaged_writer_observation.rs"));
    let pending = facade
        .split("pub struct MacOsPendingPackagedWriterObservationV1")
        .nth(1)
        .unwrap()
        .split_once("\n}")
        .unwrap();

    assert!(!pending.0.contains("derive("));
    assert!(!facade.contains("impl MacOsPendingPackagedWriterObservationV1"));
    assert_eq!(
        facade
            .matches("pub fn observe_pending_packaged_writer(")
            .count(),
        1
    );
    for forbidden in [
        "pub fn from_parts",
        "pub fn path",
        "pub fn pid",
        "pub fn audit_token",
        "pub fn digest",
        "pub fn control",
        "pub fn root",
        "pub fn verify",
        "pub fn authenticate",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
    ] {
        assert!(
            !facade.contains(forbidden),
            "forbidden Pending surface: {forbidden}"
        );
    }
}

#[test]
fn native_observation_sources_exclude_trust_time_release_and_pid_fallback() {
    let mut source = production_text(&manifest().join("src/packaged_writer_observation.rs"));
    collect_rs(
        &manifest().join("src/packaged_writer_observation"),
        &mut source,
    );
    for forbidden in [
        "SecRequirement",
        "SystemTime",
        "SignedRelease",
        "signed_release",
        "Authenticated",
        "Verified",
        "IssueTicket",
        "ProviderProfile",
        "release_authority",
        "trust_store",
        "caller_identity",
        "runne_native_enrollment_authority",
        "runne_platform_desktop",
        "runne_provider",
        "runne_secure_store",
        "runne_cli",
        "runne_runtime",
        "set_pid(",
        "SecCodeCopyPath",
        "SecCode::path(",
        "canonicalize(",
        "current_exe(",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden native primitive: {forbidden}"
        );
    }

    let security =
        production_text(&manifest().join("src/packaged_writer_observation/security_code.rs"));
    assert!(security.contains("SecCodeCheckValidity("));
    assert!(security.contains("kSecCSStrictValidate | kSecCSNoNetworkAccess"));
    assert!(security.contains("std::ptr::null_mut()"));
    assert!(security.contains("GuestAttributes::new()"));
    assert!(security.contains("attributes.set_audit_token("));
}

#[test]
fn final_gate_revalidates_package_socket_audit_start_code_and_vnodes() {
    let facade = production_text(&manifest().join("src/packaged_writer_observation.rs"));
    let peer = production_text(&manifest().join("src/local_peer.rs"));
    let process = production_text(&manifest().join("src/packaged_writer_observation/process.rs"));

    assert!(facade.matches("package.revalidate()?").count() >= 2);
    assert!(facade.matches("revalidate_same_peer(").count() >= 2);
    let last_package = facade.rfind("package.revalidate()?").unwrap();
    let last_self_process = facade
        .rfind("self_process.revalidate_self(&package)?")
        .unwrap();
    let last_peer_process = facade
        .rfind("peer_process.revalidate_peer(&package, &peer)?")
        .unwrap();
    let last_same_peer = facade.rfind("peer.revalidate_same_peer(").unwrap();
    assert!(last_self_process < last_package);
    assert!(last_peer_process < last_package);
    assert!(last_package < last_same_peer);
    for fact in [
        "same_audit_token(&self.token, &fresh.token)",
        "fresh.pid == self.pid",
        "fresh.euid == self.euid",
        "fresh.process_start_digest == self.process_start_digest",
        "fresh.socket_identity == self.socket_identity",
    ] {
        assert!(peer.contains(fact), "missing final peer fact: {fact}");
    }
    for fact in [
        "NativeCodeObservation::capture_self()?",
        "NativeCodeObservation::capture_peer(peer)?",
        "observe_start(self.pid)? == self.start",
        "require_main_locator(fresh_code.main_executable(), self.role)?",
        "observe_executable_mapping(self.pid)?",
        "== self.executable",
    ] {
        assert!(
            process.contains(fact),
            "missing live-process revalidation: {fact}"
        );
    }
}

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs(directory: &Path, source: &mut String) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs(&path, source);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            source.push_str(&production_text(&path));
        }
    }
}

fn production_text(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}
