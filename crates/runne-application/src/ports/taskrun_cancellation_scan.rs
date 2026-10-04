/// Bounded read-only scan for cancellations that may have been interrupted
/// after the request committed but before runtime terminalization.
pub trait TaskRunCancellationScanner {
    /// Returns exact current versions whose latest canonical event is a
    /// cancellation request. Completion still requires the atomic store port.
    fn scan_pending_taskrun_cancellations(
        &self,
        request: TaskRunQueueScanRequest,
    ) -> Result<TaskRunQueueScanPage, EventStoreError>;
}
