#![cfg(target_os = "macos")]
//! macOS native regression: the frozen source-path deny set versus real APFS
//! name resolution. The policy decides on NFC-normalized components with
//! ASCII-only case folding; case-insensitive APFS additionally equates the
//! Unicode simple-case-fold pair U+017F (LATIN SMALL LETTER LONG S) with
//! ASCII 's', which the ASCII-only policy does not fold. Experiments on
//! macOS 27 arm64 (SHA d0f1d7d0) confirmed that long-s variants of denied
//! names open the denied files' content while the frozen policy admits them.
//! U+212A KELVIN SIGN also folds on APFS but is covered by the policy: it has
//! a canonical decomposition to 'k', so NFC normalization denies it. ASCII
//! case, NFC/NFD forms, and non-folding lookalikes hold.

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

/// Long-s variants of denied names that case-insensitive APFS resolves onto
/// the denied files: (variant name, denied canary path, canary content).
const CONFIRMED_LONG_S_BYPASS_PAIRS: [(&str, &str, &str); 4] = [
    ("id_r\u{017F}a", "id_rsa", "CANARY-IDRSA"),
    (
        "credential\u{017F}.json",
        "credentials.json",
        "CANARY-CREDS",
    ),
    (".aw\u{017F}", ".aws", "CANARY-AWS"),
    (".\u{017F}\u{017F}h/config", ".ssh/config", "CANARY-SSHCONF"),
];

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

/// U+212A folds to 'k' on case-insensitive APFS *and* in the policy: it has a
/// canonical decomposition to ASCII, so NFC normalization denies it. Both
/// layers agree; no bypass.
#[test]
fn kelvin_sign_fold_is_covered_by_nfc_canonical_decomposition() {
    let fixture = fixture_with_mode_probe(&[("host.key", "CANARY-HOSTKEY")]);
    let variant = "host.\u{212A}ey";
    if volume_is_case_insensitive(&fixture.root) {
        assert!(
            opens_content(&fixture.root, variant, "CANARY-HOSTKEY"),
            "APFS must fold U+212A onto 'k' for this regression to stay meaningful"
        );
    }
    assert!(
        production_sensitive_path(variant),
        "policy NFC must fold U+212A to 'k' and deny the .key suffix"
    );
}

#[test]
fn non_folding_lookalikes_open_no_file() {
    let fixture = fixture_with_mode_probe(&[(".env", "CANARY-DOTENV"), (".aws", "CANARY-AWS")]);
    for variant in [
        // Fullwidth dot: compatibility character, NFC keeps it, APFS does not fold it.
        ".\u{FF0E}env",
        // Cyrillic homoglyph for 'e'.
        ".\u{0435}nv",
        // Greek final sigma and fullwidth 's' do not fold into ASCII 's'.
        ".aw\u{03C2}",
        ".aw\u{FF53}",
        // Dotless i and I-with-dot do not fold into ASCII 'i'.
        "\u{0131}d_rsa",
        "\u{0130}D_RSA",
    ] {
        assert!(
            !production_sensitive_path(variant),
            "{variant} is not fold-equivalent to a deny name; policy must admit it"
        );
        assert!(
            !opens_content(&fixture.root, variant, "CANARY-DOTENV"),
            "{variant} must not open .env content"
        );
        assert!(
            !opens_content(&fixture.root, variant, "CANARY-AWS"),
            "{variant} must not open .aws content"
        );
    }
}

/// Pins the observed APFS fold behavior this regression is built on: on a
/// case-insensitive volume the long-s variant resolves to the denied file
/// while the frozen policy admits it (the confirmed macOS bypass). If macOS
/// changes this folding, this test fails and the matrix must be re-derived.
#[test]
fn long_s_variants_reach_denied_content_on_case_insensitive_volumes() {
    let fixture = fixture_with_mode_probe(&[
        ("id_rsa", "CANARY-IDRSA"),
        ("credentials.json", "CANARY-CREDS"),
        (".aws", "CANARY-AWS"),
        (".ssh/config", "CANARY-SSHCONF"),
    ]);
    if !volume_is_case_insensitive(&fixture.root) {
        return; // Fold behavior is a property of the case-insensitive mode.
    }
    for (variant, denied, content) in CONFIRMED_LONG_S_BYPASS_PAIRS {
        assert!(
            !production_sensitive_path(variant),
            "{variant}: the frozen policy stopped admitting a long-s variant; \
             close IGNORed admission-invariant test and re-derive the matrix"
        );
        assert!(
            opens_content(&fixture.root, variant, content),
            "{variant} stopped resolving to {denied}; re-derive the fold matrix"
        );
    }
}

/// Security invariant: whatever native resolution can deliver must be denied
/// by admission. Currently VIOLATED by the long-s fold pairs (the policy
/// admits what APFS resolves onto denied files), so this test is ignored
/// until the frozen-policy owner (Linux) closes the gap. Run explicitly:
/// `cargo test -p runne-daemon --test macos_apfs_admission_matrix -- --ignored`
#[test]
#[ignore = "known bypass: case-insensitive APFS folds U+017F into deny names the frozen policy admits (owned by the frozen-policy authority)"]
fn every_resolvable_variant_of_a_denied_name_is_admission_denied() {
    let fixture = fixture_with_mode_probe(&[
        ("id_rsa", "CANARY-IDRSA"),
        ("credentials.json", "CANARY-CREDS"),
        (".aws", "CANARY-AWS"),
        (".ssh/config", "CANARY-SSHCONF"),
    ]);
    if !volume_is_case_insensitive(&fixture.root) {
        return; // Fold delivery requires the case-insensitive mode.
    }
    for (variant, denied, content) in CONFIRMED_LONG_S_BYPASS_PAIRS {
        assert!(
            production_sensitive_path(variant),
            "{variant} resolves to denied file {denied} ({content}) on this volume \
             and must be denied by admission"
        );
    }
}

#[test]
fn benign_paths_stay_resolvable() {
    let fixture = fixture_with_mode_probe(&[("notes/plan.md", "CANARY-PLAN")]);
    assert!(opens_content(&fixture.root, "notes/plan.md", "CANARY-PLAN"));
    assert!(!production_sensitive_path("notes/plan.md"));
}
