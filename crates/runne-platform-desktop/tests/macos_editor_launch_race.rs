//! Reproduction of the OPEN macOS editor-launch TOCTOU (kept for a separate
//! decision; the editor path is NOT fixed by this branch).
//!
//! Production sequence on macOS
//! (crates/runne-platform-desktop/src/root_handle_broker/unix_editor.rs):
//! `open_file_below` validates the file through the admitted root handle
//! (per-component `O_NOFOLLOW`, same-device, regular-file check) and drops the
//! descriptor; `root_path` derives the root as a path string; the joined
//! target string is handed to `/usr/bin/open`, which re-resolves it from
//! scratch. Nothing re-checks the target between validation and the
//! opener's own resolution, so a same-volume rename (or a rename of a
//! staged symlink) between the two steps swaps the delivered file. The
//! validation descriptor is dropped before the spawn, so no identity pin
//! survives to detect the swap.
//!
//! This test models the swap deterministically through public building
//! blocks AFTER the native validation step: validate via
//! `read_text_relative` (the production native opener), swap, then read the
//! path string the opener would receive. It does NOT launch the production
//! editor or `LaunchServices`, so it is a model of the swap window, not proof
//! of delivery through a actually-spawned editor. A related,
//! separately-decided defect: on macOS 27 the production launch is blocked
//! even earlier — `root_path` reads `/dev/fd/N` via readlink, which returns
//! EINVAL for every process on that OS, so every editor launch fails
//! `Unavailable` at base before the race window is even reachable; deriving
//! the path via `fcntl(F_GETPATH)` is the candidate remedy and is
//! intentionally NOT part of the integration diff (an fd-to-path change
//! re-enables a previously dead path and needs its own review).
#![cfg(target_os = "macos")]

use runne_platform_desktop::VerifiedRootHandle;

#[test]
fn editor_target_string_resolves_onto_denied_content_after_a_swap() {
    let dir = tempfile::tempdir().expect("temporary workspace");
    std::fs::create_dir_all(dir.path().join("notes")).expect("notes directory");
    std::fs::write(dir.path().join("notes/plan.md"), "CANARY-PLAN").expect("benign file");
    std::fs::write(dir.path().join(".env"), "CANARY-DOTENV").expect("denied file");
    let canonical = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    let root = VerifiedRootHandle::open(&canonical).expect("verified root");

    // Step 1 — production validation: the native opener validates and reads
    // the benign target.
    assert_eq!(
        root.read_text_relative("notes/plan.md", 4096)
            .expect("validated benign read"),
        "CANARY-PLAN"
    );

    // Step 2 — attacker window: a same-volume rename swaps the validated
    // name onto the denied file (a staged symlink swap behaves the same).
    std::fs::rename(dir.path().join(".env"), dir.path().join("notes/plan.md"))
        .expect("attacker rename");

    // Step 3 — the opener re-resolves only the path string it was handed;
    // nothing in production re-checks the target, so the denied content is
    // what the modeled opener read observes. (Modeled substitution only —
    // no production editor/LaunchServices was launched in this test.)
    let target = canonical.join("notes/plan.md");
    assert_eq!(
        std::fs::read_to_string(&target).expect("modeled opener-visible content"),
        "CANARY-DOTENV",
        "OPEN DEFECT: after the swap, the path string handed to the opener \
         resolves onto the denied file; the editor launch path is not fixed \
         by this branch"
    );
}
