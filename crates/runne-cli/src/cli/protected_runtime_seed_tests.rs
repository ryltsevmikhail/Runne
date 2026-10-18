use super::*;

#[test]
fn seed_only_command_is_recognized_as_protected_runtime_invocation() {
    let arguments = [
        "--format",
        "json",
        "permissions",
        "--protected-runtime-root",
        "/tmp/runne-seed/runtime",
        "seed-empty-root-fixture",
        "--project-root",
        "/tmp/runne-seed/project",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();

    assert!(is_seed_only_invocation(&arguments));
    assert_eq!(
        parse_invocation(arguments).expect("closed seed invocation"),
        (
            PathBuf::from("/tmp/runne-seed/runtime"),
            PathBuf::from("/tmp/runne-seed/project"),
            super::super::super::OutputFormat::Json,
        )
    );
}

#[test]
fn ordinary_permission_read_does_not_select_seed_path() {
    let arguments = [
        "permissions",
        "--protected-runtime-root",
        "/tmp/runne-seed/runtime",
        "status",
        "--workspace-id",
        "018f2e3a-7000-7000-8000-000000000001",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();

    assert!(!is_seed_only_invocation(&arguments));
}

#[test]
fn seed_path_rejects_reserved_runtime_siblings() {
    assert!(
        paths::validate(
            Path::new("/tmp/runne-seed/runtime"),
            Path::new("/tmp/runne-seed/updates"),
        )
        .is_err()
    );
    assert!(
        paths::validate(
            Path::new("/tmp/runne-seed/.runne-native-enrollment"),
            Path::new("/tmp/runne-seed/project"),
        )
        .is_err()
    );
}

#[test]
fn seed_reports_the_observed_effective_state_without_hardcoding() {
    use runne_api::{
        PermissionContainmentV1, PermissionModeNotReadyReasonV1, PermissionModeV1,
        PermissionPresetVersionV1,
    };

    let not_ready = PermissionEffectiveStateV1::NotReady {
        reason: PermissionModeNotReadyReasonV1::NativeContainment,
    };
    let not_ready = effective_state_json(&not_ready).expect("plain not_ready state serializes");
    assert_eq!(not_ready["state"], "notReady");
    assert_eq!(not_ready["reason"], "native_containment");

    let ready = PermissionEffectiveStateV1::Ready {
        mode: PermissionModeV1::AskAlways,
        preset_version: PermissionPresetVersionV1::V1,
        scope_digest: runne_domain::id::IntegrityDigest::from_bytes([0; 32]),
        containment: PermissionContainmentV1::WorkspaceBoundV1,
    };
    let ready = effective_state_json(&ready).expect("plain ready state serializes");
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["mode"], "ask_always");
}

#[test]
fn seed_refuses_existing_runtime_state_without_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = tempfile::tempdir().expect("private fixture parent");
    let runtime_root = parent.path().join("runtime");
    std::fs::create_dir(&runtime_root).expect("create existing runtime");
    std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
        .expect("make runtime private");
    let state_directory = runtime_root.join("runne-daemon");
    std::fs::create_dir(&state_directory).expect("create daemon state directory");
    let sentinel = state_directory.join("event-log.db");
    std::fs::write(&sentinel, b"existing authoritative runtime state")
        .expect("write state sentinel");
    let project_root = parent.path().join("project");

    assert!(paths::validate(&runtime_root, &project_root).is_err());
    assert!(paths::create_private_empty_runtime_root(&runtime_root).is_err());
    assert_eq!(
        std::fs::read(&sentinel).expect("preserved state sentinel"),
        b"existing authoritative runtime state"
    );
    assert!(!project_root.exists());
}

#[test]
fn seed_creates_a_new_private_empty_runtime_root() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = tempfile::tempdir().expect("private fixture parent");
    let runtime_root = parent.path().join("runtime");
    paths::create_private_empty_runtime_root(&runtime_root).expect("create new runtime root");

    let metadata = std::fs::symlink_metadata(&runtime_root).expect("runtime metadata");
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    assert!(paths::is_empty_directory(&runtime_root).expect("empty runtime root"));
}
