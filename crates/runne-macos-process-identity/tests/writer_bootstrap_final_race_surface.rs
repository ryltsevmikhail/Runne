#![cfg(target_os = "macos")]

#[test]
fn final_race_hooks_are_test_only_and_production_surface_stays_exact() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let observation =
        std::fs::read_to_string(root.join("src/packaged_writer_observation.rs")).unwrap();
    let provisional =
        std::fs::read_to_string(root.join("src/provisional_writer_session.rs")).unwrap();
    let artifact =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/artifact.rs")).unwrap();
    let process =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/process.rs")).unwrap();
    let code =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/security_code.rs"))
            .unwrap();
    let peer = std::fs::read_to_string(root.join("src/local_peer.rs")).unwrap();

    for (source, hook) in [
        (&artifact, "test_only_corrupt_digest"),
        (&process, "test_only_corrupt_start"),
        (&process, "test_only_corrupt_native_code"),
        (&code, "test_only_corrupt_main_executable"),
        (&peer, "test_only_corrupt_process_start"),
        (&observation, "test_only_inject_final_race"),
        (&provisional, "test_only_revalidate_after_final_race"),
    ] {
        let hook_position = source
            .find(hook)
            .unwrap_or_else(|| panic!("missing {hook}"));
        let cfg_position = source[..hook_position].rfind("#[cfg(test)]").unwrap();
        let guarded_prefix = &source[cfg_position..hook_position];
        assert!(guarded_prefix.contains("fn "));
        assert!(!guarded_prefix.contains('}'), "{hook} is not test-only");
    }

    let production_transition = provisional
        .split("pub fn match_current_pinned_release(")
        .nth(1)
        .unwrap()
        .split("#[cfg(feature = \"test-support\")]")
        .next()
        .unwrap();
    assert!(!production_transition.contains("test_only_"));
    let test_match = provisional
        .find("pub fn test_only_match_verified_release(")
        .unwrap();
    let test_cfg = provisional[..test_match]
        .rfind("#[cfg(feature = \"test-support\")]")
        .unwrap();
    assert!(!provisional[test_cfg..test_match].contains('}'));
    assert_eq!(
        provisional
            .matches("MacOsPendingProvisionalWriterSessionV1 {")
            .count(),
        2
    );
    for forbidden in ["SystemTime", "pub trait", "pub fn mint", "into_authority"] {
        assert!(!production_transition.contains(forbidden));
    }

    let desktop_manifest = include_str!("../../runne-platform-desktop/Cargo.toml");
    let normal = section(
        desktop_manifest,
        "[target.'cfg(target_os = \"macos\")'.dependencies]",
    );
    assert!(
        normal.contains(
            "runne-macos-process-identity = { path = \"../runne-macos-process-identity\" }"
        )
    );
    assert!(!normal.contains("test-support"));
    let dev = section(
        desktop_manifest,
        "[target.'cfg(target_os = \"macos\")'.dev-dependencies]",
    );
    assert!(dev.contains("features = [\"test-support\"]"));
}

fn section<'a>(manifest: &'a str, header: &str) -> &'a str {
    manifest
        .split(header)
        .nth(1)
        .unwrap()
        .split("\n[")
        .next()
        .unwrap()
}
