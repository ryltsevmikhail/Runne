//! Local process contracts: opaque process trees, resource-limit
//! envelopes and launch specifications. Raw PIDs are never authority —
//! ownership binds executable digest + generation + evidence.

use std::path::PathBuf;

/// Monotonic supervisor generation for one host incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostGeneration(pub u64);

/// Logical worker role generation. Identity is distinct from the host
/// generation line; exactly one worker slot exists per host generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkerGeneration(pub u64);

/// Resource-limit envelope bound to the exact launch generation and
/// containment certificate (RESOURCE_MANAGEMENT §LocalExecutionPermit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProcessLimitEnvelope {
    /// Address-space cap in bytes.
    pub address_space_bytes: u64,
    /// Resident-memory cap in bytes.
    pub resident_bytes: u64,
    /// Active-time cap in milliseconds.
    pub active_time_ms: u64,
    /// Descriptor count cap.
    pub descriptor_count: u32,
    /// Process-count cap (host + optional worker).
    pub process_count: u32,
}

/// Launch specification: absolute verified executable, cleared
/// environment, declared artifact digest and generation binding. The
/// launch key is supervisor-generated entropy, never user input.
#[derive(Debug, Clone)]
pub struct LocalProcessSpec {
    pub executable: PathBuf,
    pub host_generation: HostGeneration,
    /// Launch key material delivered via protected channel (hex).
    pub launch_key_hex: String,
    pub limits: LocalProcessLimitEnvelope,
}

/// Sanitized terminal evidence for one supervised host incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEvidence {
    pub generation: HostGeneration,
    pub exit_ok: bool,
}
