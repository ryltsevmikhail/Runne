use std::path::PathBuf;

const MARKER_FILE: &str = ".runne-test-protected-local-preapproval-stage";
const STAGES: &[&str] = &[
    "admission",
    "open_held_files",
    "sealed_snapshot",
    "preflight",
    "digest",
    "managed_area_support",
    "ready",
];

pub(super) fn begin() {
    if let Some(path) = marker_path() {
        let _ = std::fs::remove_file(path);
    }
}

pub(super) fn stage(stage: &'static str) {
    if !STAGES.contains(&stage) {
        return;
    }
    if let Some(path) = marker_path() {
        let _ = std::fs::write(path, stage.as_bytes());
    }
}

fn marker_path() -> Option<PathBuf> {
    let enabled = std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    enabled.then(|| {
        std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT")
            .map(PathBuf::from)
            .map(|root| root.join(MARKER_FILE))
    })?
}
