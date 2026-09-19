//! T1 frozen path policy invariants: deny set coverage (§G3), case folding,
//! NFC canonical equivalence, ambiguous/unsupported shape rejection (F5).

use runne_security::project_trust_policy::{
    PathRejection, denied_by_frozen_set, normalize_source_path,
};

#[test]
fn frozen_deny_set_blocks_all_components_and_suffixes() {
    for denied in [
        ".git",
        ".ssh",
        ".aws",
        ".env",
        ".netrc",
        ".npmrc",
        "id_rsa",
        "credentials.json",
    ] {
        let components = normalize_source_path(&format!("docs/{denied}/inner"))
            .expect("plain relative path normalizes");
        assert!(denied_by_frozen_set(&components), "{denied} must be denied");
    }
    for suffix in [".key", ".pem", ".p12", ".ppk", ".gpg"] {
        let components = normalize_source_path(&format!("certs/host{suffix}")).expect("normalizes");
        assert!(denied_by_frozen_set(&components), "{suffix} must be denied");
    }
    let components = normalize_source_path("notes.key.txt").expect("normalizes");
    assert!(
        !denied_by_frozen_set(&components),
        "double extension is scoped to stage-2, not auto-deny (G3)"
    );
}

#[test]
fn deny_decisions_survive_case_and_unicode_normalization() {
    for variant in [".ENV", ".Git", "ID_RSA", "Credentials.JSON"] {
        let components = normalize_source_path(&format!("docs/{variant}")).expect("normalizes");
        assert!(
            denied_by_frozen_set(&components),
            "{variant} must be denied"
        );
    }
    // Decomposed ("e" + U+0301) and precomposed é must agree.
    let decomposed = normalize_source_path("caf\u{65}\u{301}/readme.md").expect("normalizes");
    let precomposed = normalize_source_path("caf\u{e9}/readme.md").expect("normalizes");
    assert_eq!(
        decomposed, precomposed,
        "NFC normalization must be canonical"
    );
    assert_eq!(
        denied_by_frozen_set(&decomposed),
        denied_by_frozen_set(&precomposed)
    );
}

#[test]
fn ambiguous_paths_are_rejected_not_repaired() {
    for (raw, expected) in [
        ("/etc/passwd", PathRejection::Absolute),
        ("../outside", PathRejection::ParentTraversal),
        ("docs/../secrets", PathRejection::ParentTraversal),
        ("~/ssh", PathRejection::HomePrefix),
        ("docs//file", PathRejection::EmptyComponent),
        ("docs/file/", PathRejection::EmptyComponent),
        ("docs/./file", PathRejection::EmptyComponent),
        ("docs\\file", PathRejection::Backslash),
        ("docs/ma\u{0}in", PathRejection::ControlCharacter),
        // F5: Windows drive letters and ADS colons are unsupported forms.
        ("C:/secrets", PathRejection::ReservedCharacter),
        ("data/file:stream", PathRejection::ReservedCharacter),
    ] {
        assert_eq!(
            normalize_source_path(raw),
            Err(expected),
            "{raw:?} must be rejected as {expected:?}"
        );
    }
}

#[test]
fn nested_denied_component_blocks_whole_path() {
    let components = normalize_source_path("docs/deep/.ssh/config").expect("normalizes");
    assert!(denied_by_frozen_set(&components));
    let clean = normalize_source_path("docs/ssh-notes/config").expect("normalizes");
    assert!(!denied_by_frozen_set(&clean));
}
