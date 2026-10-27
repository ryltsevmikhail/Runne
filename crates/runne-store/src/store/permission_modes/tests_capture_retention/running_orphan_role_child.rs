//! Actual S-owned W/R handles; status and cleanup never reconstructed from a PID.
use super::{
    clock::Deadline,
    context::CaseContext,
    role::{self, Role},
};
use std::{
    process::{Child, ExitStatus, Stdio},
    time::Duration,
};

pub(super) struct RoleChild {
    child: Child,
    status: Option<ExitStatus>,
    deadline: Deadline,
}
impl RoleChild {
    pub(super) fn spawn(context: &CaseContext, role: Role) -> Self {
        let mut command = role::child(context, role);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        drop(command);
        Self {
            child,
            status: None,
            deadline: context.deadline,
        }
    }
    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }
    pub(super) fn live(&mut self) {
        assert!(self.status.is_none());
        self.status = self.child.try_wait().unwrap();
        assert!(
            self.status.is_none(),
            "actual role must still be owned/live"
        );
        self.deadline.check();
    }
    pub(super) fn wait(&mut self) -> ExitStatus {
        assert!(self.status.is_none());
        loop {
            self.deadline.check();
            if let Some(status) = self.child.try_wait().unwrap() {
                self.status = Some(status);
                return status;
            }
            std::thread::sleep(self.deadline.remaining().min(Duration::from_millis(1)));
        }
    }
}
impl Drop for RoleChild {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        // Failure-only cleanup, original remainingD; never kill an inferred PID.
        while let Ok(left) = self.deadline.try_remaining() {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.status = Some(status);
                    return;
                }
                Ok(None) => {
                    let _ = self.child.kill();
                }
                Err(_) => break,
            }
            std::thread::sleep(left.min(Duration::from_millis(1)));
        }
        // Retain the actual handle through fatal teardown, no false collection.
        std::hint::black_box(&self.child);
        std::process::abort();
    }
}
