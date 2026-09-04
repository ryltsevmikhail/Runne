use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::time::Duration;

use runne_platform_desktop::{
    ConfirmedInstalledNativeEnrollment, CredentialWriterHandoff, CredentialWriterHandoffError,
    CredentialWriterHandoffMode, ProtectedBundledRuntimeError, ProtectedBundledRuntimeSupervisor,
};

pub(super) struct ScopedSupervisor {
    supervisor: ProtectedBundledRuntimeSupervisor,
    writers: Vec<Rc<RefCell<CredentialWriterHandoff>>>,
}

pub(super) struct ScopedHandoff(Rc<RefCell<CredentialWriterHandoff>>);

impl ScopedSupervisor {
    pub(super) const fn new(supervisor: ProtectedBundledRuntimeSupervisor) -> Self {
        Self {
            supervisor,
            writers: Vec::new(),
        }
    }

    pub(super) fn run_credential_writer_handoff(
        &mut self,
        confirmed: &ConfirmedInstalledNativeEnrollment,
        mode: CredentialWriterHandoffMode,
    ) -> Result<ScopedHandoff, ProtectedBundledRuntimeError> {
        let result = self
            .supervisor
            .run_credential_writer_handoff(confirmed, mode);
        self.retain(result)
    }

    fn retain(
        &mut self,
        result: Result<CredentialWriterHandoff, CredentialWriterHandoffError>,
    ) -> Result<ScopedHandoff, ProtectedBundledRuntimeError> {
        match result {
            Ok(handoff) => Ok(self.keep(handoff)),
            Err(error) => {
                let (error, retained) = error.into_parts();
                if let Some(handoff) = retained {
                    self.keep(handoff);
                }
                Err(error)
            }
        }
    }

    fn keep(&mut self, handoff: CredentialWriterHandoff) -> ScopedHandoff {
        let handoff = Rc::new(RefCell::new(handoff));
        self.writers.push(Rc::clone(&handoff));
        ScopedHandoff(handoff)
    }
}

impl Deref for ScopedSupervisor {
    type Target = ProtectedBundledRuntimeSupervisor;
    fn deref(&self) -> &Self::Target {
        &self.supervisor
    }
}

impl DerefMut for ScopedSupervisor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.supervisor
    }
}

impl Drop for ScopedSupervisor {
    fn drop(&mut self) {
        let stopped = self.supervisor.stop().is_ok();
        let mut reaped = true;
        for writer in &self.writers {
            let mut writer = writer.borrow_mut();
            drop(writer.take_pair_secret_relay());
            reaped &= writer
                .reap_exact_writer_bounded(Duration::from_secs(10))
                .is_ok();
        }
        // A cleanup failure must fail the native scenario, never become a success.
        // During unwinding the scenario already fails; avoid a second panic.
        if !std::thread::panicking() {
            assert!(stopped && reaped, "native-scenario-cleanup-incomplete");
        }
    }
}

impl ScopedHandoff {
    pub(super) fn take_pair_secret_relay(
        &mut self,
    ) -> Option<runne_platform_desktop::provider_credential_broker::MacOsAuthenticatedPairSecretRelay>
    {
        self.0.borrow_mut().take_pair_secret_relay()
    }

    pub(super) fn reap_exact_writer(&mut self) -> Result<(), ProtectedBundledRuntimeError> {
        self.0.borrow_mut().reap_exact_writer()
    }

    pub(super) fn reap_exact_writer_bounded(
        &mut self,
        timeout: Duration,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        self.0.borrow_mut().reap_exact_writer_bounded(timeout)
    }
}

#[test]
fn early_return_retains_success_and_error_wait_owners() {
    for failed_handoff in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
            std::path::Path::new("/bin/sleep"),
            directory.path(),
        )
        .unwrap();
        let supervisor = ProtectedBundledRuntimeSupervisor::new(
            runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
            spec,
        );
        let (mut child, error) = runne_platform_desktop::test_only_failed_writer_handoff();
        let mut scope = ScopedSupervisor::new(supervisor);
        let result = if failed_handoff {
            Err(error)
        } else {
            Ok(error.into_parts().1.unwrap())
        };
        drop(scope.retain(result));
        child.kill().unwrap();
        drop(scope);
        assert!(
            child.wait().is_err(),
            "scope must consume the exact child wait status"
        );
    }
}
