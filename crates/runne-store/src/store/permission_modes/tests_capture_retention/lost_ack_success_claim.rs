//! Records the original real claim request and fresh receipt for the test oracle.
use runne_application::ports::*;
use std::sync::Mutex;
// Install at the genuine claim call, BEFORE target preparation discards its inputs.
// Delegate unchanged; this recorder neither allocates nor writes any authority.
pub(super) struct ClaimRecorder<'a> {
    port: &'a dyn TaskRunClaimPort,
    original: Mutex<Option<(TaskRunClaimRequest, TaskRunClaimReceipt)>>,
}
impl<'a> ClaimRecorder<'a> {
    pub(super) fn new(port: &'a dyn TaskRunClaimPort) -> Self {
        Self {
            port,
            original: Mutex::new(None),
        }
    }
    pub(super) fn take(&self) -> (TaskRunClaimRequest, TaskRunClaimReceipt) {
        self.original
            .lock()
            .unwrap()
            .take()
            .expect("one fresh original claim")
    }
}
impl TaskRunClaimPort for ClaimRecorder<'_> {
    fn lookup_task_run_claim(
        &self,
        q: TaskRunClaimLookup,
    ) -> std::result::Result<TaskRunClaimLookupResult, TaskRunClaimError> {
        self.port.lookup_task_run_claim(q)
    }
    fn claim_task_run(
        &self,
        q: TaskRunClaimRequest,
    ) -> std::result::Result<TaskRunClaimResult, TaskRunClaimError> {
        let mut slot = self.original.lock().unwrap();
        assert!(slot.is_none(), "fresh fixture must claim once");
        let saved = q.clone();
        let result = self.port.claim_task_run(q)?;
        let TaskRunClaimResult::Committed(receipt) = &result else {
            panic!("original fixture claim must be fresh")
        };
        *slot = Some((saved, receipt.clone()));
        Ok(result)
    }
}
