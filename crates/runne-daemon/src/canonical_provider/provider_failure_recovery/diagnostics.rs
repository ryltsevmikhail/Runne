#[derive(Clone, Copy)]
pub(super) enum RecoveryFailureStage {
    MissingPreEffectProof,
    JournalRecovery,
    UnknownReplay,
    TerminalAssembly,
    TerminalStatus,
    ScannerRead,
    ScannerDisposition,
    SettlementProof,
    CancellationStatus,
    CancellationApply,
    FailureApply,
    ConversationLoad,
    SubmittedMessageProof,
    StartedReceiptLoad,
    StartedReceiptBinding,
    FinishApplication,
}

#[cfg(test)]
impl RecoveryFailureStage {
    const fn token(self) -> &'static str {
        match self {
            Self::MissingPreEffectProof => "missing_pre_effect_proof",
            Self::JournalRecovery => "journal_recovery",
            Self::UnknownReplay => "unknown_replay",
            Self::TerminalAssembly => "terminal_assembly",
            Self::TerminalStatus => "terminal_status",
            Self::ScannerRead => "scanner_read",
            Self::ScannerDisposition => "scanner_disposition",
            Self::SettlementProof => "settlement_proof",
            Self::CancellationStatus => "cancellation_status",
            Self::CancellationApply => "cancellation_apply",
            Self::FailureApply => "failure_apply",
            Self::ConversationLoad => "conversation_load",
            Self::SubmittedMessageProof => "submitted_message_proof",
            Self::StartedReceiptLoad => "started_receipt_load",
            Self::StartedReceiptBinding => "started_receipt_binding",
            Self::FinishApplication => "finish_application",
        }
    }
}

#[cfg(test)]
pub(super) fn recovery_failure(stage: RecoveryFailureStage) {
    eprintln!("provider_failure_recovery_stage={}", stage.token());
}

#[cfg(not(test))]
pub(super) fn recovery_failure(_: RecoveryFailureStage) {}
