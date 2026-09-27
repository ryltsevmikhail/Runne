#[derive(Clone, Copy)]
pub enum Stage {
    InstallStarted,
    ActivationLeaseConsumed,
    ProtectedTransportAccepted,
    ProtectedTransportRejected,
    ProfileLoaded,
    PeerVerified,
    BootstrapProved,
    Authenticated,
    ClientInstalled,
    Reconciling,
    RecoverySkippedNoSecurity,
    RecoveryStarted,
    RecoveryClientUnavailable,
    RecoveryBindingUnavailable,
    RecoveryStoreUnavailable,
    RecoveryStoreLocked,
    RecoveryEvidenceUnavailable,
    RecoveryEvidenceLoaded,
    RecoveryEvidenceExhausted,
    RecoveryLeaseUnavailable,
    RecoveryLeaseRecovered,
    RecoveryPreparedClosed,
    ReconcileStarted,
    ReconcileComplete,
    ReconcileFailed,
    ReconcileFailedTerminal,
    RecoveryComplete,
    InstallRecoveryFailed,
    InstallLive,
}

impl Stage {
    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    const fn code(self) -> &'static str {
        match self {
            Self::InstallStarted => "install_started",
            Self::ActivationLeaseConsumed => "activation_lease_consumed",
            Self::ProtectedTransportAccepted => "protected_transport_accepted",
            Self::ProtectedTransportRejected => "protected_transport_rejected",
            Self::ProfileLoaded => "profile_loaded",
            Self::PeerVerified => "peer_verified",
            Self::BootstrapProved => "bootstrap_proved",
            Self::Authenticated => "authenticated",
            Self::ClientInstalled => "client_installed",
            Self::Reconciling => "reconciling",
            Self::RecoverySkippedNoSecurity => "recovery_skipped_no_security",
            Self::RecoveryStarted => "recovery_started",
            Self::RecoveryClientUnavailable => "recovery_client_unavailable",
            Self::RecoveryBindingUnavailable => "recovery_binding_unavailable",
            Self::RecoveryStoreUnavailable => "recovery_store_unavailable",
            Self::RecoveryStoreLocked => "recovery_store_locked",
            Self::RecoveryEvidenceUnavailable => "recovery_evidence_unavailable",
            Self::RecoveryEvidenceLoaded => "recovery_evidence_loaded",
            Self::RecoveryEvidenceExhausted => "recovery_evidence_exhausted",
            Self::RecoveryLeaseUnavailable => "recovery_lease_unavailable",
            Self::RecoveryLeaseRecovered => "recovery_lease_recovered",
            Self::RecoveryPreparedClosed => "recovery_prepared_closed",
            Self::ReconcileStarted => "reconcile_started",
            Self::ReconcileComplete => "reconcile_complete",
            Self::ReconcileFailed => "reconcile_failed",
            Self::ReconcileFailedTerminal => "reconcile_failed_terminal",
            Self::RecoveryComplete => "recovery_complete",
            Self::InstallRecoveryFailed => "install_recovery_failed",
            Self::InstallLive => "install_live",
        }
    }
}

pub fn record(stage: Stage) {
    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "runne-app-core-qualification-stage={}",
            stage.code()
        );
    }

    #[cfg(not(all(target_os = "linux", feature = "linux-native-enrollment-qualification")))]
    let _ = stage;
}
