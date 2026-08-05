//! Process contract qualification status constants.

/// The process contract defines types but permits no native execution.
pub const PROCESS_CONTRACT_STATUS: &str = "CONTRACT_ONLY";

/// No native sandbox backend has qualified for execution.
pub const NATIVE_SANDBOX_STATUS: &str = "NATIVE_SANDBOX_NOT_QUALIFIED";
