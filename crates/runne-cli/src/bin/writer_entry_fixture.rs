//! TEST-ONLY fixture binary (feature `writer-entry-fixture`; never built in
//! production): enters the REAL shared early-entry sweep routine (the exact
//! production source file) and reports dummy known facts for the regression
//! test. The feature enables no authority or alternate writer behavior.

#[path = "../cli/provider_credential_broker/writer_fd_sweep.rs"]
mod writer_fd_sweep;

fn main() {
    let swept = writer_fd_sweep::close_inherited_descriptors_production();
    writer_fd_sweep::report_sweep_facts();
    std::process::exit(match swept {
        Ok(()) => 0,
        Err(_) => 1,
    });
}
