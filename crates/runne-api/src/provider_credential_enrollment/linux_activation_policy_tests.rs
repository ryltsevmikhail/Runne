//! Activation-policy tests: default OFF, DeepSeek-only allowlist, exact
//! installation/host binding, typed JSON roundtrip, and fail-closed loading
//! with permission-checked fixtures (T10). No real machine-id, activation
//! record, or host policy is ever read or written.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

use super::*;

pub(super) fn record() -> LinuxEnrollmentActivationRecord {
    LinuxEnrollmentActivationRecord {
        provider_scope: LinuxEnrollmentScope::LegacyDeepSeek,
        runtime_root_digest: [1; 32],
        desktop_image_digest: [2; 32],
        writer_image_digest: [3; 32],
        daemon_image_digest: [4; 32],
        runtime_authority_id: [5; 16],
        machine_id_digest: [6; 32],
        approved_at_unix_millis: 1_700_000_000_000,
    }
}

pub(super) fn facts() -> LinuxInstallationFacts {
    LinuxInstallationFacts {
        runtime_root_digest: [1; 32],
        desktop_image_digest: [2; 32],
        writer_image_digest: [3; 32],
        daemon_image_digest: [4; 32],
        runtime_authority_id: [5; 16],
        machine_id_digest: [6; 32],
    }
}

fn write_fixture(path: &std::path::Path, bytes: &[u8], mode: u32) {
    let mut file = std::fs::File::create(path).expect("fixture create");
    file.write_all(bytes).expect("fixture write");
    let mut permissions = file.metadata().expect("fixture metadata").permissions();
    permissions.set_mode(mode);
    file.set_permissions(permissions).expect("fixture chmod");
}

#[test]
fn missing_record_denies_by_default() {
    assert_eq!(
        evaluate_linux_enrollment(None, &facts(), Some(LinuxEnrollmentProvider::DEEP_SEEK)),
        LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::PolicyAbsent)
    );
}

#[test]
fn non_allowlisted_provider_denies_even_with_matching_record() {
    assert_eq!(
        evaluate_linux_enrollment(Some(&record()), &facts(), None),
        LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::ProviderNotAllowed)
    );
}

#[test]
fn approved_fixture_with_matching_facts_allows_deepseek() {
    assert_eq!(
        evaluate_linux_enrollment(
            Some(&record()),
            &facts(),
            Some(LinuxEnrollmentProvider::DEEP_SEEK)
        ),
        LinuxEnrollmentDecision::Allowed
    );
}

#[test]
fn copied_record_on_other_host_or_installation_denies_each_field() {
    for mutated in [
        LinuxInstallationFacts {
            runtime_root_digest: [9; 32],
            ..facts()
        },
        LinuxInstallationFacts {
            desktop_image_digest: [9; 32],
            ..facts()
        },
        LinuxInstallationFacts {
            writer_image_digest: [9; 32],
            ..facts()
        },
        LinuxInstallationFacts {
            daemon_image_digest: [9; 32],
            ..facts()
        },
        LinuxInstallationFacts {
            runtime_authority_id: [9; 16],
            ..facts()
        },
        LinuxInstallationFacts {
            machine_id_digest: [9; 32],
            ..facts()
        },
    ] {
        assert_eq!(
            evaluate_linux_enrollment(
                Some(&record()),
                &mutated,
                Some(LinuxEnrollmentProvider::DEEP_SEEK)
            ),
            LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::InstallationMismatch)
        );
    }
}

#[test]
fn zero_approval_time_is_not_a_valid_binding() {
    let mut invalid = record();
    invalid.approved_at_unix_millis = 0;
    assert_eq!(
        evaluate_linux_enrollment(
            Some(&invalid),
            &facts(),
            Some(LinuxEnrollmentProvider::DEEP_SEEK)
        ),
        LinuxEnrollmentDecision::Denied(LinuxEnrollmentDenial::InstallationMismatch)
    );
}

#[test]
fn provider_mapping_is_closed() {
    assert_eq!(
        LinuxEnrollmentProvider::from_id("deepseek"),
        Some(LinuxEnrollmentProvider::DEEP_SEEK)
    );
    for other in ["unknown-provider", "DeepSeek", "deepseek ", ""] {
        assert_eq!(LinuxEnrollmentProvider::from_id(other), None);
    }
}

#[test]
fn config_json_roundtrips_exactly() {
    let json = record().to_config_json();
    assert_eq!(
        LinuxEnrollmentActivationRecord::from_config_json(&json),
        Some(record())
    );
}

#[test]
fn config_json_rejects_structural_deviation() {
    let json = record().to_config_json();
    for malformed in [
        String::new(),
        json.replacen("runne.linux-enrollment-activation.v1", "other-schema", 1),
        json.replacen(TD1_APPROVAL_MARKER, "other-approval", 1),
        format!("{}{}", &json[..json.len() - 1], ",\"extra\":1}"),
    ] {
        assert_eq!(
            LinuxEnrollmentActivationRecord::from_config_json(&malformed),
            None
        );
    }
}

#[test]
fn canonicalizer_binds_live_authority_and_all_images() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("fixture root");
    let daemon_dir = root.path().join("runne-daemon");
    std::fs::create_dir(&daemon_dir).expect("daemon dir");
    let mut authority = std::fs::File::create(daemon_dir.join(AUTHORITY_SIDECAR_FILE)).unwrap();
    authority.write_all(&[7_u8; 16]).unwrap();
    let mut permissions = authority.metadata().unwrap().permissions();
    permissions.set_mode(0o600);
    authority.set_permissions(permissions).unwrap();
    for image in ["runne-desktop", "runne", "runned"] {
        std::fs::write(root.path().join(image), b"image-bytes").unwrap();
    }
    let machine = root.path().join("machine-id");
    std::fs::write(&machine, b"host-machine").unwrap();
    let desktop = root.path().join("runne-desktop");
    let writer = root.path().join("runne");
    let daemon_image = root.path().join("runned");
    let layout = LinuxInstallationLayout {
        runtime_root: root.path(),
        desktop_image: &desktop,
        writer_image: &writer,
        daemon_image: &daemon_image,
        machine_id_path: &machine,
    };
    let facts = layout.canonicalize_facts([7; 16]).unwrap();
    assert_eq!(facts.runtime_authority_id, [7; 16]);
    assert_eq!(facts.desktop_image_digest, facts.writer_image_digest);
    assert_eq!(Some(facts.machine_id_digest), file_digest(&machine));
    assert_ne!(facts.runtime_root_digest, [0; 32]);
}

#[test]
fn missing_empty_or_nonregular_artifacts_never_produce_facts() {
    let root = tempfile::tempdir().unwrap();
    let image = root.path().join("artifact");
    let layout = LinuxInstallationLayout {
        runtime_root: root.path(),
        desktop_image: &image,
        writer_image: &image,
        daemon_image: &image,
        machine_id_path: &image,
    };
    assert!(layout.canonicalize_facts([7; 16]).is_none());
    std::fs::write(&image, []).unwrap();
    assert!(layout.canonicalize_facts([7; 16]).is_none());
    std::fs::write(&image, b"measurable-bytes").unwrap();
    assert!(layout.canonicalize_facts([7; 16]).is_some());
    assert!(layout.canonicalize_facts([0; 16]).is_none());
    std::fs::remove_file(&image).unwrap();
    std::fs::create_dir(&image).unwrap();
    assert!(layout.canonicalize_facts([7; 16]).is_none());
}
