//! TEST-ONLY fixture binary (feature `writer-entry-fixture`; never built in
//! production): enters the REAL shared early-entry sweep routine (the exact
//! production source file) and reports dummy known facts for the regression
//! test. The feature enables no authority or alternate writer behavior.

use std::io::Write as _;

// Source-includes the REAL production sweep module so the fixture exercises
// the exact audited code; this test-only bin lives outside src/ so the
// production source tree keeps zero out-of-tree path references.
#[path = "../src/cli/provider_credential_broker/writer_fd_sweep.rs"]
mod writer_fd_sweep;

fn main() {
    let swept = writer_fd_sweep::close_inherited_descriptors_except(
        writer_fd_sweep::enumerate_proc_fds,
        None,
    );
    report_sweep_facts();
    std::process::exit(match swept {
        Ok(()) => 0,
        Err(_) => 1,
    });
}

/// Reports the post-sweep surviving descriptors and inherited environment
/// names. Lives only in this fixture binary, never in the production CLI.
fn report_sweep_facts() {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "ENV-START");
    for (name, value) in std::env::vars_os() {
        let _ = writeln!(out, "{}={}", name.display(), value.display());
    }
    let _ = writeln!(out, "ENV-END");
    let _ = writeln!(out, "FD-START");
    if let Ok(inventory) = std::fs::read_dir("/proc/self/fd") {
        for entry in inventory.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let target = std::fs::read_link(format!("/proc/self/fd/{name}"))
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default();
            let _ = writeln!(out, "{name}\t{target}");
        }
    }
    let _ = writeln!(out, "FD-END");
}
