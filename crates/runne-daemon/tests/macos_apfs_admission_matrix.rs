#![cfg(target_os = "macos")]
//! macOS native regression for the T1 source-path admission.
//!
//! The file separates two concerns that must not be conflated:
//!
//! 1. Observed APFS name equivalence — which requested names resolve onto
//!    which existing files on a case-insensitive volume. This is a property
//!    of the filesystem and carries no policy expectation.
//! 2. The admission security invariant — whatever native resolution can
//!    deliver must be denied by the policy. This is the security claim.
//!
//! Experiments on macOS 27 arm64 confirmed that U+017F (LATIN SMALL LETTER
//! LONG S) and U+212A (KELVIN SIGN) fold into ASCII on case-insensitive
//! APFS. Revision 1 of the frozen policy (ASCII-only case folding) admitted
//! the long-s variants, so the invariant test fails on revision 1 by design
//! and stays in the normal (non-ignored) suite: it turns green exactly when
//! the policy revision covers the fold (revision 2 intentionally over-denies
//! here). NFC/NFD forms, ASCII case, and non-folding lookalikes hold.

use runne_platform_desktop::VerifiedRootHandle;
use runne_security::project_trust_policy::{denied_by_frozen_set, normalize_source_path};

const MAX_READ: usize = 4096;

/// Production composition of the admission deny check, mirroring
/// `RootAdmissionGateway`'s `sensitive_path`
/// (crates/runne-daemon/src/application/root_handle_admission/diff_baseline.rs:48-55,
/// backed by the frozen policy in crates/runne-security). Kept as a literal
/// mirror so this test observes exactly what production admission decides.
fn production_sensitive_path(path: &str) -> bool {
    !path.is_empty()
        && normalize_source_path(path)
            .map(|components| denied_by_frozen_set(&components))
            .unwrap_or(true)
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: VerifiedRootHandle,
}

fn fixture(files: &[(&str, &str)]) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary workspace");
    for (name, content) in files {
        let target = dir.path().join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent directory");
        }
        std::fs::write(&target, content).expect("fixture file");
    }
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical fixture path");
    let root = VerifiedRootHandle::open(&canonical).expect("verified root");
    Fixture { _dir: dir, root }
}

/// Every fixture gets the mode probe; a case-insensitive volume answers both
/// spellings, a case-sensitive one only the exact one.
fn fixture_with_mode_probe(files: &[(&str, &str)]) -> Fixture {
    let mut all = vec![("mode_probe.txt", "mode")];
    all.extend_from_slice(files);
    fixture(&all)
}

fn opens_content(root: &VerifiedRootHandle, name: &str, expected: &str) -> bool {
    root.read_text_relative(name, MAX_READ)
        .is_ok_and(|content| content == expected)
}

/// Whether the fixture volume folds file-name case (default macOS APFS).
fn volume_is_case_insensitive(root: &VerifiedRootHandle) -> bool {
    opens_content(root, "MODE_PROBE.txt", "mode")
}

/// Names that case-insensitive APFS resolves onto an existing denied file:
/// (variant name, existing denied file, that file's unique canary content).
/// U+017F folds to ASCII 's', U+212A folds to ASCII 'k'; the `.ssh` pair
/// shows the fold also applies to a directory component mid-path. This is
/// observed filesystem behavior only — no admission expectation attaches.
const APFS_FOLD_EQUIVALENCE_PAIRS: [(&str, &str, &str); 5] = [
    ("id_r\u{017F}a", "id_rsa", "CANARY-IDRSA"),
    (
        "credential\u{017F}.json",
        "credentials.json",
        "CANARY-CREDS",
    ),
    (".aw\u{017F}", ".aws", "CANARY-AWS"),
    (".\u{017F}\u{017F}h/config", ".ssh/config", "CANARY-SSHCONF"),
    ("host.\u{212A}ey", "host.key", "CANARY-HOSTKEY"),
];

#[test]
fn fold_pairs_resolve_onto_their_existing_files_on_case_insensitive_volumes() {
    let fixture = fixture_with_mode_probe(&[
        ("id_rsa", "CANARY-IDRSA"),
        ("credentials.json", "CANARY-CREDS"),
        (".aws", "CANARY-AWS"),
        (".ssh/config", "CANARY-SSHCONF"),
        ("host.key", "CANARY-HOSTKEY"),
    ]);
    if !volume_is_case_insensitive(&fixture.root) {
        return; // Fold behavior is a property of the case-insensitive mode.
    }
    for (variant, existing, content) in APFS_FOLD_EQUIVALENCE_PAIRS {
        assert!(
            opens_content(&fixture.root, variant, content),
            "{variant} must resolve onto the existing file {existing} on this volume"
        );
    }
}

/// Security invariant: every variant that native resolution can deliver
/// (proven above) must be denied by admission. Red on policy revision 1 by
/// design — that is the documented macOS bypass — and green once the policy
/// revision covers the fold; it stays in the normal (non-ignored) suite.
#[test]
fn every_resolvable_variant_of_a_denied_name_is_admission_denied() {
    let fixture = fixture_with_mode_probe(&[
        ("id_rsa", "CANARY-IDRSA"),
        ("credentials.json", "CANARY-CREDS"),
        (".aws", "CANARY-AWS"),
        (".ssh/config", "CANARY-SSHCONF"),
        ("host.key", "CANARY-HOSTKEY"),
    ]);
    if !volume_is_case_insensitive(&fixture.root) {
        return; // The fold only delivers on the case-insensitive mode.
    }
    for (variant, existing, content) in APFS_FOLD_EQUIVALENCE_PAIRS {
        assert!(
            opens_content(&fixture.root, variant, content),
            "precondition: {variant} resolves onto {existing} on this volume"
        );
        assert!(
            production_sensitive_path(variant),
            "{variant} resolves onto denied file {existing} ({content}) and must be denied"
        );
    }
}

#[test]
fn ascii_case_variants_are_denied_and_open_the_same_file() {
    let fixture = fixture_with_mode_probe(&[(".env", "CANARY-DOTENV")]);
    for variant in [".ENV", ".Env", ".eNv"] {
        assert!(
            production_sensitive_path(variant),
            "{variant} must be denied"
        );
        if volume_is_case_insensitive(&fixture.root) {
            assert!(
                opens_content(&fixture.root, variant, "CANARY-DOTENV"),
                "{variant} must resolve to the denied file on a case-insensitive volume"
            );
        }
    }
}

#[test]
fn normalization_forms_name_one_file_and_stay_denied() {
    let fixture =
        fixture_with_mode_probe(&[("caf\u{E9}.md", "CANARY-NFC"), (".env", "CANARY-DOTENV")]);
    // The volume keeps NFC and NFD spellings of the same name as one file...
    assert!(opens_content(&fixture.root, "cafe\u{301}.md", "CANARY-NFC"));
    // ...and the policy NFC-normalizes, so both spellings decide identically.
    let nfc = normalize_source_path("caf\u{E9}.md").expect("NFC path");
    let nfd = normalize_source_path("cafe\u{301}.md").expect("NFD path");
    assert_eq!(nfc, nfd);
    assert!(!denied_by_frozen_set(&nfc));
    // Deny components are pure ASCII, so normalization cannot hide them.
    assert!(production_sensitive_path(".env"));
}

/// Non-folding lookalikes name no existing file: each negative case is
/// checked against its real target file and that target's unique canary
/// (including the id_rsa fixture for the dotless-i / I-with-dot cases).
/// No admission expectation attaches (a revision may intentionally
/// over-deny); the security-relevant half is that nothing resolves.
#[test]
fn non_folding_lookalikes_deliver_no_canary() {
    let fixture = fixture_with_mode_probe(&[
        (".env", "CANARY-DOTENV"),
        (".aws", "CANARY-AWS"),
        ("id_rsa", "CANARY-IDRSA"),
    ]);
    if !volume_is_case_insensitive(&fixture.root) {
        return;
    }
    // (variant, real target, that target's canary) — the variant opens none.
    let cases: [(&str, &str, &str); 6] = [
        (".\u{FF0E}env", ".env", "CANARY-DOTENV"),
        (".\u{0435}nv", ".env", "CANARY-DOTENV"),
        (".aw\u{03C2}", ".aws", "CANARY-AWS"),
        (".aw\u{FF53}", ".aws", "CANARY-AWS"),
        ("\u{0131}d_rsa", "id_rsa", "CANARY-IDRSA"),
        ("\u{0130}D_RSA", "id_rsa", "CANARY-IDRSA"),
    ];
    for (variant, target, canary) in cases {
        assert!(
            !opens_content(&fixture.root, variant, canary),
            "{variant} must not deliver {target} content"
        );
    }
}

#[test]
fn benign_paths_stay_resolvable() {
    let fixture = fixture_with_mode_probe(&[("notes/plan.md", "CANARY-PLAN")]);
    assert!(opens_content(&fixture.root, "notes/plan.md", "CANARY-PLAN"));
    assert!(!production_sensitive_path("notes/plan.md"));
}
