//! Shared Linux boot-elapsed deadline; suspend consumes, never extends, budget.
//! Safe text access respects runne-store's forbid(unsafe_code).
use std::time::Duration;
pub(super) const ENV: &str = "RUNNE_G3_CANCEL_DEADLINE_NS";
const TICK: u64 = 10_000_000;
#[derive(Clone, Copy)]
pub(super) struct Deadline(pub u64);
fn now() -> u64 {
    let text = std::fs::read_to_string("/proc/uptime").unwrap();
    assert!(text.len() <= 128);
    let first = text.split_whitespace().next().unwrap();
    let (seconds, fraction) = first.split_once('.').unwrap();
    assert!(!seconds.is_empty() && seconds.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(fraction.len(), 2);
    assert!(fraction.bytes().all(|b| b.is_ascii_digit()));
    seconds
        .parse::<u64>()
        .unwrap()
        .checked_mul(1_000_000_000)
        .unwrap()
        .checked_add(fraction.parse::<u64>().unwrap() * TICK)
        .unwrap()
}
impl Deadline {
    // proc uptime floors to centiseconds. Reserve one tick so the real elapsed
    // interval cannot exceed 20s (or 2s for phases) due to that quantization.
    pub fn new() -> Self {
        Self(now().checked_add(20_000_000_000 - TICK).unwrap())
    }
    pub fn inherited() -> Self {
        let value = Self(std::env::var(ENV).unwrap().parse().unwrap());
        assert!(value.live());
        assert!(value.0.saturating_sub(now()) <= 20_000_000_000);
        value
    }
    pub fn live(self) -> bool {
        now() < self.0
    }
    pub fn check(self) {
        assert!(self.live(), "shared history deadline");
    }
    pub fn phase(self) -> Self {
        self.check();
        Self(self.0.min(now() + 2_000_000_000 - TICK))
    }
    pub fn remaining(self) -> Duration {
        let left = self
            .0
            .checked_sub(now())
            .and_then(|v| v.checked_sub(TICK))
            .expect("positive conservative phase budget");
        assert!(left > 0);
        Duration::from_nanos(left)
    }
}
