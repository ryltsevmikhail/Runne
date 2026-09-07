//! Resource enforcement (Plan Task 12): converts the admitted quote
//! into the exact process-limit envelope, runs an identity-bound
//! pressure monitor that starts BEFORE model load, and records
//! terminal measured peak/limit evidence. Crossing the warning
//! threshold stops admission; crossing the hard threshold fences
//! output, sends a bounded cancel and terminates the worker tree —
//! the supervisor stays alive and records the evidence. An estimate
//! alone never authorizes native execution.

use runne_engine_platform::LocalProcessLimitEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureThresholds {
    /// Fraction of the envelope where admission stops (0..=100).
    pub warning_percent: u8,
    /// Fraction where output is fenced and cleanup runs (0..=100).
    pub hard_percent: u8,
}

impl PressureThresholds {
    pub const fn defaults() -> Self {
        Self {
            warning_percent: 80,
            hard_percent: 95,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureDisposition {
    WithinLimits,
    /// Warning crossed: admission stops, nothing native starts.
    WarningAdmissionStopped,
    /// Hard crossed: fence output + cancel + terminate worker tree.
    HardFenced,
}

/// Identity-bound monitor state. `measured_peak_bytes` is injected by
/// the platform (real RSS sampling is the Phase 6B qualification);
/// the policy here is deterministic.
#[derive(Debug)]
pub struct PressureMonitor {
    identity: [u8; 16],
    envelope: LocalProcessLimitEnvelope,
    thresholds: PressureThresholds,
    started: bool,
    peak_bytes: u64,
    terminated: bool,
}

impl PressureMonitor {
    /// Starts the monitor; must be called before model load.
    pub fn start_before_load(
        identity: [u8; 16],
        envelope: LocalProcessLimitEnvelope,
        thresholds: PressureThresholds,
    ) -> Self {
        Self {
            identity,
            envelope,
            thresholds,
            started: true,
            peak_bytes: 0,
            terminated: false,
        }
    }

    pub fn identity(&self) -> [u8; 16] {
        self.identity
    }

    pub fn started(&self) -> bool {
        self.started
    }

    /// Reports one physical-footprint sample and classifies it.
    pub fn sample(&mut self, resident_bytes: u64) -> PressureDisposition {
        self.peak_bytes = self.peak_bytes.max(resident_bytes);
        let warn = u128::from(self.envelope.resident_bytes)
            * u128::from(self.thresholds.warning_percent)
            / 100;
        let hard = u128::from(self.envelope.resident_bytes)
            * u128::from(self.thresholds.hard_percent)
            / 100;
        if u128::from(self.peak_bytes) >= hard {
            self.terminated = true;
            return PressureDisposition::HardFenced;
        }
        if u128::from(self.peak_bytes) >= warn {
            return PressureDisposition::WarningAdmissionStopped;
        }
        PressureDisposition::WithinLimits
    }

    /// Terminal evidence: measured peak vs limits, recorded once.
    pub fn terminal_evidence(&self) -> Option<PressureEvidence> {
        if !self.started {
            return None;
        }
        Some(PressureEvidence {
            identity: self.identity,
            peak_bytes: self.peak_bytes,
            limit_bytes: self.envelope.resident_bytes,
            terminated: self.terminated,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureEvidence {
    pub identity: [u8; 16],
    pub peak_bytes: u64,
    pub limit_bytes: u64,
    pub terminated: bool,
}

/// Converts an admitted quote into the exact process-limit envelope:
/// resident = quote RAM, address space = resident + shared slack,
/// active time = quote, descriptors/processes from the one-worker
/// model.
pub fn envelope_for(ram_bytes: u64, active_time_ms: u64) -> LocalProcessLimitEnvelope {
    LocalProcessLimitEnvelope {
        address_space_bytes: ram_bytes.saturating_add(512 * 1024 * 1024),
        resident_bytes: ram_bytes,
        active_time_ms,
        descriptor_count: 64,
        process_count: 2, // host + worker
    }
}
