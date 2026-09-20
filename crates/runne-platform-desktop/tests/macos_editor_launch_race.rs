//! Editor-launch boundary models: classification fixtures, not defect
//! reproductions.
//!
//! Production state on macOS
//! (crates/runne-platform-desktop/src/root_handle_broker/unix_editor.rs):
//! the launcher path has been REMOVED BY DECISION.
//! `launch_system_default_editor` validates the file through the admitted
//! root handle (`open_file_below`: per-component `O_NOFOLLOW`, same-device,
//! regular-file check) and then deterministically returns the existing typed
//! `Unavailable` — a deliberate, temporary macOS-backend limitation. No
//! opener is spawned and no path string is handed to anything on macOS.
//!
//! What these tests therefore model is the general property of any
//! path-string handoff design (as still used on the Linux backend): a path
//! string is re-resolved by whoever receives it, and workspace objects can
//! be replaced under an unchanged name at any time. They pin that property
//! through public building blocks only and launch no production editor or
//! `LaunchServices`, so none of them is a proven production exploit.
//!
//! The OS observation that motivated the earlier macOS launcher design is
//! recorded separately by the opt-in diagnostic
//! `macos_devfd_readlink_observation.rs` (`--ignored`): ONE observation of
//! `readlink` on `/dev/fd/N` on ONE host running ONE macOS build — not a
//! claim about all processes or macOS versions.
#![cfg(target_os = "macos")]

use runne_platform_desktop::VerifiedRootHandle;

/// Replacement of the OBJECT under an ALLOWED name — ordinary mutability of
/// workspace objects, not a boundary crossing: the denied NAME (`.env`) is
/// never opened, and an opener resolving the path string simply sees
/// whatever object currently bears the allowed name. Pinned so this
/// mutability is not misread as a defect.
#[test]
fn allowed_name_object_replacement_is_ordinary_workspace_mutability() {
    let dir = tempfile::tempdir().expect("temporary workspace");
    std::fs::create_dir_all(dir.path().join("notes")).expect("notes directory");
    std::fs::write(dir.path().join("notes/plan.md"), "CANARY-PLAN").expect("benign file");
    std::fs::write(dir.path().join(".env"), "CANARY-DOTENV").expect("denied-name file");
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    let root = VerifiedRootHandle::open(&canonical).expect("verified root");

    // Step 1 — production validation: the native opener validates and reads
    // the benign target.
    assert_eq!(
        root.read_text_relative("notes/plan.md", 4096)
            .expect("validated benign read"),
        "CANARY-PLAN"
    );

    // Step 2 — the object under the allowed name is replaced (a plain
    // workspace rename). The denied NAME `.env` is never opened; only the
    // object identity behind the allowed name changes, as it may at any
    // time.
    std::fs::rename(dir.path().join(".env"), dir.path().join("notes/plan.md"))
        .expect("object replacement under the allowed name");

    // Step 3 — mutability pin: an opener resolving the path string observes
    // whatever object currently holds the allowed name. (Modeled resolution
    // only — no production editor/LaunchServices was launched in this test;
    // on macOS the production launch itself is refused by decision.)
    let target = canonical.join("notes/plan.md");
    assert_eq!(
        std::fs::read_to_string(&target).expect("modeled opener-visible content"),
        "CANARY-DOTENV",
        "mutability pin: the path string handed to an opener resolves onto \
         whatever object currently holds the allowed name; the denied name \
         `.env` was never opened"
    );
}

/// Ordinary mutability of an ALLOWED file is not a boundary crossing: the
/// opener sees whatever the allowed file currently contains, and a deny-set
/// name is never involved. Same mutability principle as the object-replacement
/// pin above — content mutation instead of object identity.
#[test]
fn allowed_file_content_mutation_is_not_a_boundary_crossing() {
    let dir = tempfile::tempdir().expect("temporary workspace");
    std::fs::create_dir_all(dir.path().join("notes")).expect("notes directory");
    std::fs::write(dir.path().join("notes/plan.md"), "VERSION-1").expect("allowed file");
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    let root = VerifiedRootHandle::open(&canonical).expect("verified root");

    assert_eq!(
        root.read_text_relative("notes/plan.md", 4096)
            .expect("validated read"),
        "VERSION-1"
    );
    std::fs::write(dir.path().join("notes/plan.md"), "VERSION-2").expect("content edit");
    assert_eq!(
        std::fs::read_to_string(canonical.join("notes/plan.md")).expect("opener-visible content"),
        "VERSION-2",
        "the allowed file's own content may change at any time; no denied name is involved"
    );
}

/// RISK MODEL of the potential editor-side re-resolution of a path string:
/// after validating the in-root file, renaming a symlink that points
/// OUTSIDE the workspace onto the validated name makes the path string
/// handed to an opener resolve outside the admitted root. At validation
/// time the same symlink shape is rejected by `O_NOFOLLOW` — the production
/// boundary holds before the swap. This is a model of a residual risk for
/// any future path-string handoff design, NOT a proven production exploit:
/// the macOS production launch is refused by decision (see the module doc)
/// and no production editor was launched here.
#[test]
fn post_validation_symlink_swap_is_an_editor_reresolution_risk_model() {
    let dir = tempfile::tempdir().expect("temporary workspace");
    let outside = tempfile::tempdir().expect("outside root");
    std::fs::create_dir_all(dir.path().join("notes")).expect("notes directory");
    std::fs::write(dir.path().join("notes/plan.md"), "CANARY-PLAN").expect("allowed file");
    std::fs::write(outside.path().join("secret.txt"), "CANARY-OUTSIDE").expect("outside canary");
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    let root = VerifiedRootHandle::open(&canonical).expect("verified root");

    // The boundary itself holds: a symlink in place at validation time is
    // rejected by the native opener (`O_NOFOLLOW`).
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        dir.path().join("notes/escape"),
    )
    .expect("staged escape symlink");
    assert!(
        root.read_text_relative("notes/escape", 4096).is_err(),
        "native validation must reject a symlink component"
    );

    // Validate the benign in-root file, THEN swap the name onto the outside
    // symlink: the string the opener receives now resolves outside the root.
    assert_eq!(
        root.read_text_relative("notes/plan.md", 4096)
            .expect("validated read"),
        "CANARY-PLAN"
    );
    let staged = dir.path().join("notes/escape-src");
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), &staged)
        .expect("staged escape symlink");
    std::fs::rename(&staged, dir.path().join("notes/plan.md"))
        .expect("post-validation symlink swap");
    assert_eq!(
        std::fs::read_to_string(canonical.join("notes/plan.md"))
            .expect("modeled opener-visible content"),
        "CANARY-OUTSIDE",
        "RISK MODEL: a post-validation symlink swap makes the path string an \
         opener receives resolve outside the admitted root; NOT a proven \
         production exploit — the macOS launch is refused by decision"
    );
}
