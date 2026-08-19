use std::sync::atomic::{AtomicBool, Ordering};

use runne_tools::{
    ProcessAuthorizationAuthorityV1, ProcessStubDisposition, SandboxQualificationProbe,
};

pub(super) struct AdvanceAuthorizationProbe {
    authority: ProcessAuthorizationAuthorityV1,
    advanced: AtomicBool,
}

impl AdvanceAuthorizationProbe {
    pub(super) fn new(authority: ProcessAuthorizationAuthorityV1) -> Self {
        Self {
            authority,
            advanced: AtomicBool::new(false),
        }
    }
}

impl SandboxQualificationProbe for AdvanceAuthorizationProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        if !self.advanced.swap(true, Ordering::SeqCst) {
            self.authority.prepare_advance().unwrap().commit().unwrap();
        }
        Ok(())
    }
}
