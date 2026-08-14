use super::{DIGEST, UPPER, assert_usage, command};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::process::Command;

#[test]
fn release_rejects_uppercase_for_every_command_and_non_utf8_values() {
    for arguments in [
        vec![
            "release",
            "rc1",
            "qualify",
            "--dry-run",
            "--subject-sha256",
            DIGEST,
            "--matrix-sha256",
            DIGEST,
            "--bootstrap-sha256",
            DIGEST,
            "--candidate-sha256",
            DIGEST,
            "--policy-sha256",
            UPPER,
        ],
        vec![
            "release",
            "rc2",
            "authorize",
            "--dry-run",
            "--candidate-sha256",
            DIGEST,
            "--rc1-decision-sha256",
            DIGEST,
            "--unsigned-candidate-manifest-sha256",
            DIGEST,
            "--linux-pre-sign-sha256",
            DIGEST,
            "--linux-pre-sign-length",
            "1",
            "--windows-pre-sign-sha256",
            DIGEST,
            "--windows-pre-sign-length",
            "2",
            "--workflow-sha256",
            DIGEST,
            "--effect-namespace",
            "release-native-sign",
            "--effect-generation",
            "1",
            "--signing-policy-sha256",
            UPPER,
        ],
        vec![
            "release",
            "rc2",
            "verify",
            "--dry-run",
            "--candidate-sha256",
            DIGEST,
            "--signed-envelope-inventory-sha256",
            DIGEST,
            "--threshold-update-metadata-set-sha256",
            DIGEST,
            "--verification-report-sha256",
            UPPER,
        ],
        vec![
            "release",
            "rc3",
            "authorize",
            "--dry-run",
            "--candidate-sha256",
            DIGEST,
            "--signed-envelope-inventory-sha256",
            DIGEST,
            "--threshold-update-metadata-set-sha256",
            DIGEST,
            "--verification-report-sha256",
            DIGEST,
            "--publication-manifest-sha256",
            UPPER,
        ],
    ] {
        assert_usage(&arguments);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_gocode"))
        .args([
            OsString::from("release"),
            OsString::from("rc1"),
            OsString::from("qualify"),
            OsString::from("--dry-run"),
            OsString::from("--subject-sha256"),
            OsString::from_vec(vec![0xff]),
        ])
        .output()
        .expect("run command");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn release_help_is_root_stage_and_operation_specific() {
    for arguments in [
        ["release", "--help"].as_slice(),
        ["release", "rc1", "--help"].as_slice(),
        ["release", "rc2", "verify", "--help"].as_slice(),
    ] {
        assert!(
            command(arguments)
                .output()
                .expect("run help")
                .status
                .success()
        );
    }
}

#[test]
fn rc2_authorization_rejects_noncanonical_or_out_of_range_numbers() {
    for invalid in ["0", "01", "18446744073709551616", "+1", " 1"] {
        let arguments = [
            "release",
            "rc2",
            "authorize",
            "--dry-run",
            "--candidate-sha256",
            DIGEST,
            "--rc1-decision-sha256",
            DIGEST,
            "--unsigned-candidate-manifest-sha256",
            DIGEST,
            "--linux-pre-sign-sha256",
            DIGEST,
            "--linux-pre-sign-length",
            invalid,
            "--windows-pre-sign-sha256",
            DIGEST,
            "--windows-pre-sign-length",
            "2",
            "--workflow-sha256",
            DIGEST,
            "--effect-namespace",
            "release-native-sign",
            "--effect-generation",
            "1",
            "--signing-policy-sha256",
            DIGEST,
        ];
        assert_usage(&arguments);
    }
}
