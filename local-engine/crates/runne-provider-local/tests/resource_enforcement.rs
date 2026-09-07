//! Resource enforcement (Plan Task 12): quote → exact limit envelope,
//! identity-bound monitor started before load, warning stops
//! admission, hard fences + terminates, terminal evidence recorded.

use runne_provider_local::resource_enforcement::{
    PressureDisposition, PressureMonitor, PressureThresholds, envelope_for,
};

#[test]
fn envelope_matches_admitted_quote() {
    let ram = 6 * 1024 * 1024 * 1024u64;
    let envelope = envelope_for(ram, 20_480);
    assert_eq!(envelope.resident_bytes, ram);
    assert!(envelope.address_space_bytes > ram, "shared slack");
    assert_eq!(envelope.active_time_ms, 20_480);
    assert_eq!(envelope.process_count, 2, "host + worker");
}

#[test]
fn warning_crossing_stops_admission_hard_crossing_fences() {
    let ram = 4 * 1024 * 1024 * 1024u64;
    let envelope = envelope_for(ram, 60_000);
    let mut monitor =
        PressureMonitor::start_before_load([7; 16], envelope, PressureThresholds::defaults());
    assert!(monitor.started(), "started before model load");
    assert_eq!(
        monitor.sample(1024 * 1024 * 1024),
        PressureDisposition::WithinLimits
    );
    // Peak tracking: 85% of 4 GiB crosses the 80% warning.
    let warning = ram * 85 / 100;
    assert_eq!(
        monitor.sample(warning),
        PressureDisposition::WarningAdmissionStopped
    );
    // Peak stays at max; 96% crosses the 95% hard line.
    let hard = ram * 96 / 100;
    assert_eq!(monitor.sample(hard), PressureDisposition::HardFenced);
    let evidence = monitor.terminal_evidence().expect("evidence");
    assert_eq!(evidence.peak_bytes, hard, "peak is the maximum sample");
    assert!(evidence.terminated);
    assert_eq!(evidence.identity, [7; 16]);
}

#[test]
fn estimate_alone_never_authorizes_native_execution() {
    // A monitor that never observed samples carries a zero peak: the
    // estimate alone produced no measured evidence, so nothing native
    // may be authorized from it.
    let ram = 1024 * 1024 * 1024u64;
    let envelope = envelope_for(ram, 1000);
    let idle =
        PressureMonitor::start_before_load([2; 16], envelope, PressureThresholds::defaults());
    let evidence = idle.terminal_evidence().expect("idle evidence");
    assert_eq!(evidence.peak_bytes, 0);
    assert!(!evidence.terminated);
}
