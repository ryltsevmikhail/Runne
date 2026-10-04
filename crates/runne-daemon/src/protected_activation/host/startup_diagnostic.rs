use crate::error::{DaemonError, RuntimeStoreOpenStage, RuntimeStoreRejection};
use std::path::PathBuf;

const MARKER_FILE: &str = ".runne-test-protected-startup-stage";

pub(super) struct StartupDiagnostic {
    marker: Option<PathBuf>,
}

impl StartupDiagnostic {
    pub(super) fn new() -> Self {
        let marker = if enabled() {
            std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT")
                .map(PathBuf::from)
                .map(|root| root.join(MARKER_FILE))
        } else {
            None
        };
        if let Some(marker) = marker.as_ref() {
            let _ = std::fs::remove_file(marker);
        }
        Self { marker }
    }

    pub(super) fn failed(&self, stage: &'static str, reason: &str) {
        let Some(marker) = self.marker.as_ref() else {
            return;
        };
        let record = format!("{stage}:{reason}");
        let _ = std::fs::write(marker, record.as_bytes());
    }
}

pub(super) fn daemon_error_reason(error: &DaemonError) -> String {
    match error {
        DaemonError::Config(_) => "config".to_owned(),
        DaemonError::Io(_) => "io".to_owned(),
        DaemonError::Lock(_) => "lock".to_owned(),
        DaemonError::Bootstrap(message) => {
            if let Some(stage) = message.strip_prefix("reconcile retained local-command attempts: ")
            {
                return if [
                    "scan",
                    "renew_node_lease",
                    "authorize",
                    "load_stream",
                    "replay_stream",
                    "mark_unconfirmed",
                    "prove_empty",
                    "settle_unknown",
                    "remove_area",
                    "request_stop",
                    "check_area",
                    "confirm_stop",
                    "complete_cancellation",
                    "missing_exit_code",
                    "complete_taskrun",
                    "missing_terminal_event",
                    "settle_terminal",
                    "area_populated_at_terminal",
                    "unexpected_terminal_state",
                ]
                .contains(&stage)
                {
                    format!("local_recovery_{stage}")
                } else {
                    "local_recovery_unrecognized".to_owned()
                };
            }
            match message.as_str() {
                "reconcile retained local-command attempts" => "local_recovery".to_owned(),
                "settle old TaskRun assignments" => "taskrun_assignment_recovery".to_owned(),
                "settle cancelled pre-effect rejections" => "pre_effect_recovery".to_owned(),
                _ => "bootstrap".to_owned(),
            }
        }
        DaemonError::Schema(_) => "schema".to_owned(),
        DaemonError::StoreOpenRejection(rejection) => {
            let purpose = match rejection.purpose.as_str() {
                "replay store" => "replay",
                "runtime writer" => "writer",
                "runtime reader" => "reader",
                "bootstrap reservation store" => "reservation",
                _ => "other",
            };
            let stage = match rejection.stage {
                RuntimeStoreOpenStage::Open => "open",
                RuntimeStoreOpenStage::Verify => "verify",
            };
            let reason = match &rejection.rejection {
                RuntimeStoreRejection::IdentityMismatch => "identity",
                RuntimeStoreRejection::Admission(_) => "admission",
                RuntimeStoreRejection::Unavailable => "unavailable",
            };
            format!("store_{purpose}_{stage}_{reason}")
        }
    }
}

fn enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    }
    #[cfg(not(target_os = "linux"))]
    false
}
