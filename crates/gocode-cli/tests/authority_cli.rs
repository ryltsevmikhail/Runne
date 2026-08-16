#![cfg(unix)]

use std::process::Command;

#[test]
fn authority_mutations_fail_closed_before_native_store_access_off_macos() {
    if cfg!(target_os = "macos") {
        return;
    }
    for arguments in [
        vec!["authority", "init", "--trust-out", "docs/trust.json"],
        vec![
            "authority",
            "sign",
            "--trust-config",
            "docs/trust.json",
            "--receipt-out",
            "docs/evidence/receipt.json",
        ],
        vec![
            "authority",
            "rotate",
            "--trust-config",
            "docs/trust.json",
            "--rotation-out",
            "docs/rotation.json",
            "--successor-trust-out",
            "docs/successor.json",
        ],
        vec![
            "authority",
            "backup",
            "--trust-config",
            "docs/trust.json",
            "--output",
            "/tmp/backup.json",
        ],
        vec![
            "authority",
            "restore",
            "--trust-config",
            "docs/trust.json",
            "--input",
            "/tmp/backup.json",
        ],
        vec![
            "authority",
            "trust-reset",
            "--trust-config",
            "docs/trust.json",
            "--ack-compromise",
            "COMPROMISE-0123456789ab",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_gocode"))
            .args(arguments)
            .output()
            .expect("run CLI");
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout, b"");
        assert_eq!(output.stderr, b"UNSUPPORTED_PLATFORM\n");
    }
}

#[test]
fn authority_parser_rejects_yes_unknown_and_extra_arguments() {
    for arguments in [
        vec!["authority", "sign", "--yes"],
        vec!["authority", "unknown"],
        vec!["authority", "verify", "extra"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_gocode"))
            .args(arguments)
            .output()
            .expect("run CLI");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"");
        assert_eq!(output.stderr, b"USAGE\n");
    }
}

#[test]
fn authority_verify_accepts_only_the_explicit_trust_receipt_and_anchor_contract() {
    let binary = env!("CARGO_BIN_EXE_gocode");
    let valid = Command::new(binary)
        .args([
            "authority",
            "verify",
            "--trust-config",
            "docs/missing-trust.json",
            "--receipt",
            "docs/missing-receipt.json",
            "--anchor-epoch",
            "1",
            "--anchor-trust-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .output()
        .expect("run CLI");
    assert_eq!(valid.status.code(), Some(1));
    assert_eq!(valid.stderr, b"ARTIFACT_IO\n");

    let obsolete = Command::new(binary)
        .args([
            "authority",
            "verify",
            "--object-format",
            "sha1",
            "--commit",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--tree",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .output()
        .expect("run CLI");
    assert_eq!(obsolete.status.code(), Some(2));
    assert_eq!(obsolete.stderr, b"USAGE\n");
}

#[test]
fn authority_accepts_only_the_exact_typed_mutation_flags_before_platform_denial() {
    if cfg!(target_os = "macos") {
        return;
    }
    let binary = env!("CARGO_BIN_EXE_gocode");
    for arguments in [
        vec!["authority", "init", "--trust-out", "docs/trust.json"],
        vec![
            "authority",
            "sign",
            "--trust-config",
            "docs/trust.json",
            "--receipt-out",
            "docs/evidence/receipt.json",
        ],
        vec![
            "authority",
            "rotate",
            "--trust-config",
            "docs/trust.json",
            "--rotation-out",
            "docs/rotation.json",
            "--successor-trust-out",
            "docs/successor.json",
        ],
        vec![
            "authority",
            "backup",
            "--trust-config",
            "docs/trust.json",
            "--output",
            "/tmp/backup.json",
        ],
        vec![
            "authority",
            "restore",
            "--trust-config",
            "docs/trust.json",
            "--input",
            "/tmp/backup.json",
        ],
        vec![
            "authority",
            "trust-reset",
            "--trust-config",
            "docs/trust.json",
            "--ack-compromise",
            "COMPROMISE-0123456789ab",
        ],
    ] {
        let output = Command::new(binary)
            .args(arguments)
            .output()
            .expect("run CLI");
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stderr, b"UNSUPPORTED_PLATFORM\n");
    }
}

#[test]
fn authority_help_is_closed_and_root_usage_mentions_authority() {
    let binary = env!("CARGO_BIN_EXE_gocode");
    let help = Command::new(binary)
        .args(["authority", "--help"])
        .output()
        .expect("run authority help");
    assert_eq!(help.status.code(), Some(0));
    assert_eq!(help.stderr, b"");
    assert_eq!(
        help.stdout,
        b"authority: init sign verify rotate backup restore trust-reset (no --yes)\n"
    );
    let root = Command::new(binary).output().expect("run root usage");
    assert_eq!(root.status.code(), Some(2));
    assert!(
        std::str::from_utf8(&root.stderr)
            .expect("utf8 usage")
            .contains("gocode authority")
    );
}
