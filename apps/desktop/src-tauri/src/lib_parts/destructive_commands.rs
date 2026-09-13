use runne_app_core::{
    DestructiveConfirmationContext, DestructiveConfirmationLease,
    DestructiveConfirmationFuture, DestructiveConfirmationPort, DestructiveProjectSummary,
    ProjectDestructiveOperation,
};
use serde::Deserialize;
#[cfg(not(test))]
use tauri_plugin_dialog::{MessageDialogButtons, MessageDialogKind};

use crate::destructive_intent::{DestructiveIntentManager, DestructiveIntentRef};

struct DesktopConfirmationPort {
    window: WebviewWindow,
    intents: DestructiveIntentManager,
    generation: u64,
    locale: NativeConfirmationLocale,
    issued: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<PrepareDestructiveOutcome>>>,
    reference: std::sync::Mutex<Option<DestructiveIntentRef>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeConfirmationLocale {
    English,
    Russian,
}

enum PrepareDestructiveOutcome {
    Intent(DestructiveIntentRef),
    Cancelled,
    Rejected,
}

impl DesktopConfirmationPort {
    fn signal(&self, outcome: PrepareDestructiveOutcome) -> bool {
        self.issued
            .lock()
            .ok()
            .and_then(|mut issued| issued.take())
            .and_then(|sender| sender.send(outcome).ok())
            .is_some()
    }

    fn finish(&self, result: Result<(), ()>) {
        if let Ok(mut reference) = self.reference.lock()
            && let Some(reference) = reference.take()
        {
            self.intents.finish(&reference, result);
        }
        if result.is_err() {
            self.signal(PrepareDestructiveOutcome::Rejected);
        }
    }
}

impl Drop for DesktopConfirmationPort {
    fn drop(&mut self) { self.finish(Err(())); }
}

struct DesktopConfirmationLease {
    intents: DestructiveIntentManager,
    reference: DestructiveIntentRef,
    binding: runne_app_core::MutationAdmissionBinding,
    digest: [u8; 32],
    decision: Option<tokio::sync::oneshot::Receiver<bool>>,
    committed: bool,
}

impl DestructiveConfirmationLease for DesktopConfirmationLease {
    fn wait_for_consume<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let Some(decision) = self.decision.take() else { return false; };
            tokio::time::timeout(std::time::Duration::from_secs(30), decision)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false)
        })
    }

    fn try_commit(&mut self) -> bool {
        let committed = self.intents
            .try_commit(&self.reference, self.binding, self.digest, std::time::Instant::now());
        self.committed = committed;
        committed
    }
}

impl Drop for DesktopConfirmationLease {
    fn drop(&mut self) {
        if !self.committed {
            self.intents.finish(&self.reference, Err(()));
        }
    }
}

impl DestructiveConfirmationPort for DesktopConfirmationPort {
    fn confirm(
        &self,
        context: DestructiveConfirmationContext,
    ) -> DestructiveConfirmationFuture<'_> {
        Box::pin(async move {
            if !native_confirmation(&self.window, context.summary(), self.locale).await {
                self.signal(PrepareDestructiveOutcome::Cancelled);
                return None;
            }
            let (reference, decision) = self
                .intents
                .issue(
                    self.window.label(),
                    self.generation,
                    context.binding(),
                    context.action_digest(),
                    std::time::Instant::now(),
                )
                .ok()?;
            let stored = self.reference.lock().map(|mut slot| {
                *slot = Some(reference.clone());
            }).is_ok();
            let issued = stored && self.signal(PrepareDestructiveOutcome::Intent(reference.clone()));
            if !issued {
                self.finish(Err(()));
                return None;
            }
            Some(Box::new(DesktopConfirmationLease {
                intents: self.intents.clone(),
                reference,
                binding: context.binding(),
                digest: context.action_digest(),
                decision: Some(decision),
                committed: false,
            }) as Box<dyn DestructiveConfirmationLease>)
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareDestructiveProjectRequest {
    project_id: String,
    expected_version: u64,
    operation: String,
    renderer_generation: u64,
    locale: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DispatchDestructiveProjectRequest {
    intent: DestructiveIntentRef,
    renderer_generation: u64,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn prepare_destructive_project_action(
    window: WebviewWindow,
    core: State<'_, Arc<AppCore>>,
    intents: State<'_, DestructiveIntentManager>,
    request: PrepareDestructiveProjectRequest,
) -> Result<DestructiveIntentRef, IpcError> {
    let operation = parse_destructive_operation(&request.operation)?;
    let locale = parse_confirmation_locale(&request.locale)?;
    if !window.is_focused().map_err(|_| rejected())?
        || window.state::<DirectorySelectionManager>().renderer_generations().current(window.label()).ok()
            != Some(request.renderer_generation) {
        return Err(rejected());
    }
    let project_id = runne_app_core::CanonicalId::parse(&request.project_id)
        .map_err(|_| rejected())?;
    let (issued, receive)=tokio::sync::oneshot::channel();
    let port=Arc::new(DesktopConfirmationPort { window: window.clone(), intents: (*intents).clone(), generation: request.renderer_generation, locale, issued: std::sync::Mutex::new(Some(issued)), reference: std::sync::Mutex::new(None) });
    let task_port=Arc::clone(&port); let task_core=Arc::clone(&core);
    tauri::async_runtime::spawn(async move {
        let result = task_core
            .execute_destructive_project_action(
                operation,
                project_id,
                request.expected_version,
                task_port.as_ref(),
            )
            .await
            .map(|_| ())
            .map_err(|_| ());
        task_port.finish(result);
    });
    drop(port);
    match receive.await.unwrap_or(PrepareDestructiveOutcome::Rejected) {
        PrepareDestructiveOutcome::Intent(intent) => Ok(intent),
        PrepareDestructiveOutcome::Cancelled => Err(cancelled()),
        PrepareDestructiveOutcome::Rejected => Err(rejected()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn dispatch_destructive_project_action(
    window: WebviewWindow,
    intents: State<'_, DestructiveIntentManager>,
    request: DispatchDestructiveProjectRequest,
) -> Result<(), IpcError> {
    if !window.is_focused().map_err(|_| rejected())?
        || window.state::<DirectorySelectionManager>().renderer_generations().current(window.label()).ok()
            != Some(request.renderer_generation) {
        return Err(rejected());
    }
    let completion = intents
        .consume(&request.intent, window.label(), request.renderer_generation, std::time::Instant::now())
        .map_err(|_| rejected())?;
    completion.await.map_err(|_| rejected())?.map_err(|()| rejected())?;
    Ok(())
}

fn parse_destructive_operation(value: &str) -> Result<ProjectDestructiveOperation, IpcError> {
    match value {
        "archive" => Ok(ProjectDestructiveOperation::Archive),
        "delete" => Ok(ProjectDestructiveOperation::Delete),
        _ => Err(IpcError { code: "COMMAND_CONTRACT_NOT_PUBLISHED" }),
    }
}

const fn rejected() -> IpcError { IpcError { code: "destructive_action_rejected" } }
const fn cancelled() -> IpcError { IpcError { code: "destructive_action_cancelled" } }

fn parse_confirmation_locale(value: &str) -> Result<NativeConfirmationLocale, IpcError> {
    match value {
        "en" => Ok(NativeConfirmationLocale::English),
        "ru" => Ok(NativeConfirmationLocale::Russian),
        _ => Err(rejected()),
    }
}

#[cfg(not(test))]
async fn native_confirmation(
    window: &WebviewWindow,
    summary: DestructiveProjectSummary,
    locale: NativeConfirmationLocale,
) -> bool {
    let handle = window.app_handle().clone();
    let parent = window.clone();
    let (title, message, confirm, cancel) = confirmation_copy(
        locale,
        summary.operation(),
        summary.project_id(),
        summary.display_name(),
        summary.impacted_workspaces(),
    );
    tauri::async_runtime::spawn_blocking(move || {
        handle.dialog().message(message).title(title)
            .parent(&parent)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(confirm, cancel))
            .blocking_show()
    }).await.unwrap_or(false)
}

fn confirmation_copy(
    locale: NativeConfirmationLocale,
    operation: ProjectDestructiveOperation,
    project_id: runne_app_core::CanonicalId,
    display_name: &str,
    impacted_workspaces: u16,
) -> (String, String, String, String) {
    let reference = short_project_reference(project_id);
    let (title, action, confirm, cancel, impact, reference_label) = match locale {
        NativeConfirmationLocale::English => {
            let (title, action) = match operation {
                ProjectDestructiveOperation::Archive => ("Archive project?", "Archive"),
                ProjectDestructiveOperation::Delete => ("Delete project?", "Delete"),
            };
            let impact = match impacted_workspaces {
                0 => "No workspaces are attached.".to_owned(),
                1 => "1 workspace will be affected.".to_owned(),
                count => format!("{count} workspaces will be affected."),
            };
            (title, action, "Confirm", "Cancel", impact, "Project ref")
        }
        NativeConfirmationLocale::Russian => {
            let (title, action) = match operation {
                ProjectDestructiveOperation::Archive => ("Архивировать проект?", "Архивировать"),
                ProjectDestructiveOperation::Delete => ("Удалить проект?", "Удалить"),
            };
            let impact = match impacted_workspaces {
                0 => "Workspace не будет затронут.".to_owned(),
                1 => "Будет затронут 1 workspace.".to_owned(),
                count => format!("Будут затронуты {count} workspace."),
            };
            (title, action, "Подтвердить", "Отмена", impact, "Код проекта")
        }
    };
    (
        title.to_owned(),
        format!("{action} «{display_name}»?\n\n{impact}\n{reference_label}: {reference}"),
        confirm.to_owned(),
        cancel.to_owned(),
    )
}

fn short_project_reference(project_id: runne_app_core::CanonicalId) -> String {
    let value = project_id.to_string();
    format!("…{}", &value[value.len().saturating_sub(8)..])
}

#[cfg(test)]
async fn native_confirmation(
    _: &WebviewWindow,
    summary: DestructiveProjectSummary,
    _: NativeConfirmationLocale,
) -> bool {
    std::future::ready(confirmed_for_test(summary)).await
}

#[cfg(test)]
fn confirmed_for_test(_: DestructiveProjectSummary) -> bool { true }

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> runne_app_core::MutationAdmissionBinding {
        runne_app_core::MutationAdmissionBinding {
            runtime_identity_digest: [1; 32], principal_digest: [2; 32], gate_epoch: 3,
        }
    }

    #[tokio::test]
    async fn committed_lease_drop_leaves_completion_to_task_port() {
        let manager = DestructiveIntentManager::new(std::time::Duration::from_secs(30)).unwrap();
        let now = std::time::Instant::now();
        let (reference, decision) = manager.issue("main", 7, binding(), [4; 32], now).unwrap();
        let completion = manager.consume(&reference, "main", 7, now).unwrap();
        assert!(decision.await.unwrap());
        let mut lease = DesktopConfirmationLease {
            intents: manager.clone(), reference: reference.clone(), binding: binding(),
            digest: [4; 32], decision: None, committed: false,
        };
        assert!(lease.try_commit());
        drop(lease);
        manager.clear_pending();
        manager.finish(&reference, Ok(()));
        assert!(completion.await.unwrap().is_ok());
    }

    #[test]
    fn unpublished_operation_fails_before_native_confirmation() {
        let Err(error) = parse_destructive_operation("runtime_stop") else { panic!("unsupported command accepted") };
        assert_eq!(error.code, "COMMAND_CONTRACT_NOT_PUBLISHED");
    }

    #[test]
    fn confirmation_copy_is_compact_and_redacts_runtime_identifiers() {
        let project_id = runne_app_core::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").unwrap();
        let (title, message, confirm, cancel) = confirmation_copy(
            NativeConfirmationLocale::English,
            ProjectDestructiveOperation::Delete,
            project_id,
            "Selected folder",
            1,
        );
        assert_eq!(title, "Delete project?");
        assert_eq!(message, "Delete «Selected folder»?\n\n1 workspace will be affected.\nProject ref: …00000913");
        assert_eq!((confirm.as_str(), cancel.as_str()), ("Confirm", "Cancel"));
        assert!(!message.contains("version"));
        assert!(!message.contains(&project_id.to_string()));
    }

    #[test]
    fn confirmation_copy_localizes_native_actions() {
        let project_id = runne_app_core::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000913").unwrap();
        let (title, message, confirm, cancel) = confirmation_copy(
            NativeConfirmationLocale::Russian,
            ProjectDestructiveOperation::Archive,
            project_id,
            "Selected folder",
            2,
        );
        assert_eq!(title, "Архивировать проект?");
        assert!(message.contains("Архивировать «Selected folder»?"));
        assert!(message.contains("Будут затронуты 2 workspace."));
        assert_eq!((confirm.as_str(), cancel.as_str()), ("Подтвердить", "Отмена"));
    }
}
