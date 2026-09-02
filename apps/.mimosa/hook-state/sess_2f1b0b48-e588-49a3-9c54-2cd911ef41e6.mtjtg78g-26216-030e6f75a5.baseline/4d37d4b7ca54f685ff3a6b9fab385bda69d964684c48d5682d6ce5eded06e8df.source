struct ApprovalDialogSpec {
    title: String,
    message: String,
    confirm_label: String,
}

fn approval_dialog_spec(
    binding: &runne_app_core::ApprovalConfirmationBinding,
) -> ApprovalDialogSpec {
    let subject = format!(
        "{} on {} for TaskRun {}",
        binding.action(),
        binding.resource(),
        binding.task_run_id()
    );
    match binding.decision() {
        runne_app_core::ApprovalDecisionDto::Approve => ApprovalDialogSpec {
            title: "Approve runtime action".into(),
            message: format!("Approve {subject}?"),
            confirm_label: "Approve".into(),
        },
        runne_app_core::ApprovalDecisionDto::Deny => ApprovalDialogSpec {
            title: "Deny runtime action".into(),
            message: format!("Deny {subject}?"),
            confirm_label: "Deny".into(),
        },
    }
}

fn dialog_result(result: Result<bool, ()>) -> bool {
    result.unwrap_or(false)
}
