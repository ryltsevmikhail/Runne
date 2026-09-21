//! Test-support-only closed step tracing for native writer launch paths.

/// Test-support-only closed step tracer for native writer launch paths.
/// Gated behind the test-support feature and an explicit environment opt-in;
/// emits static step names and data-less error variant names only.
#[cfg(feature = "test-support")]
pub fn enabled() -> bool {
    std::env::var_os("RUNNE_WRITER_HANDOFF_TRACE").is_some_and(|value| !value.is_empty())
}

#[cfg(not(feature = "test-support"))]
pub const fn enabled() -> bool {
    false
}

#[cfg(feature = "test-support")]
pub fn step(step: &str) {
    if enabled() {
        eprintln!("writer-handoff-step={step}");
    }
}

#[cfg(not(feature = "test-support"))]
pub const fn step(_step: &str) {}

#[cfg(feature = "test-support")]
pub fn step_failed(step: &str) {
    if enabled() {
        eprintln!("writer-handoff-step-failed={step}");
    }
}

#[cfg(not(feature = "test-support"))]
pub const fn step_failed(_step: &str) {}
