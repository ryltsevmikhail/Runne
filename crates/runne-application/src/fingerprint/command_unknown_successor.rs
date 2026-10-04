use crate::commands::SupersedeUnknownTaskRunInput;

impl CommandFingerprint {
    /// Binds the predecessor, exact displayed stream version, and closed
    /// duplicate-execution-and-cost acknowledgment.
    pub fn for_supersede_unknown_task_run(input: &SupersedeUnknownTaskRunInput) -> Self {
        let mut hasher = begin(TAG_SUPERSEDE_UNKNOWN_TASK_RUN);
        hasher.update(input.predecessor_taskrun_id.as_bytes());
        hasher.update(input.expected_predecessor_version.to_be_bytes());
        hasher.update(input.acknowledgment.version().to_be_bytes());
        update_string(&mut hasher, input.acknowledgment.code());
        Self(hasher.finalize().into())
    }
}
