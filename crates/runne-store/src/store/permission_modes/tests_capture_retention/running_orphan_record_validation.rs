//! Keep actual collected status if existing assertion-based root validation fails.
use super::context::CaseContext;
use super::record_pump::Failure;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitStatus;

fn preserve(status: ExitStatus, check: impl FnOnce()) -> Result<(), Failure> {
    // No global panic hook changes. All original root/model/deadline checks run.
    // H is ALREADY COLLECTED; this adapter is never used around a live Child.
    catch_unwind(AssertUnwindSafe(check))
        .map_err(|_| Failure::collected("post-collection root validation failed", status))
}

pub(super) fn after_collection(context: &CaseContext, status: ExitStatus) -> Result<(), Failure> {
    preserve(status, || context.check_roots())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn validation_error_retains_status_without_claiming_a_live_child() {
        // Synthetic status tests error propagation ONLY, never real collection.
        let synthetic = ExitStatus::from_raw(0);
        assert!(preserve(synthetic, || {}).is_ok());
        let error = preserve(synthetic, || panic!("injected root validation failure")).unwrap_err();
        assert_eq!(error.status, Some(synthetic));
        assert!(error.uncollected.is_none());
        assert_eq!(error.primary, "post-collection root validation failed");
    }
}
