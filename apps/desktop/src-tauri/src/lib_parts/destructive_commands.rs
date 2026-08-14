use gocode_app_core::{
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
    issued: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<DestructiveIntentRef>>>,
    reference: std::sync::Mutex<Option<DestructiveIntentRef>>,
}

impl DesktopConfirmationPort {
    fn finish(&self, result: Result<(), ()>) {
        if let Ok(mut reference) = self.reference.lock()
            && let Some(reference) = reference.take()
        {
            self.intents.finish(&reference, result);
        }
    }
}

impl Drop for DesktopConfirmationPort {
    fn drop(&mut self) { self.finish(Err(())); }
}

struct DesktopConfirmationLease {
    intents: DestructiveIntentManager,
    reference: DestructiveIntentRef,
    binding: gocode_app_core::MutationAdmissionBinding,
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
            if !native_confirmation(&self.window, context.summary()).await {
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
            let issued = self
                .reference
                .lock()
                .ok()
                .and_then(|mut slot| {
                    *slot = Some(reference.clone());
                    self.issued.lock().ok().and_then(|mut issued| {
                        issued.take().map(|sender| sender.send(reference.clone()).is_ok())
                    })
                })
                .unwrap_or(false);
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
#[serde(rename_all = "camelCase")]
struct PrepareDestructiveProjectRequest {
    project_id: String,
    expected_version: u64,
    operation: String,
    renderer_generation: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
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
    if !window.is_focused().map_err(|_| rejected())?
        || window.state::<DirectorySelectionManager>().renderer_generations().current(window.label()).ok()
            != Some(request.renderer_generation) {
        return Err(rejected());
    }
    let project_id = gocode_app_core::CanonicalId::parse(&request.project_id)
        .map_err(|_| rejected())?;
    let (issued, receive)=tokio::sync::oneshot::channel();
    let port=Arc::new(DesktopConfirmationPort { window: window.clone(), intents: (*intents).clone(), generation: request.renderer_generation, issued: std::sync::Mutex::new(Some(issued)), reference: std::sync::Mutex::new(None) });
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
    receive.await.map_err(|_|rejected())
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

#[cfg(not(test))]
async fn native_confirmation(window: &WebviewWindow, summary: DestructiveProjectSummary) -> bool {
    let handle = window.app_handle().clone();
    let parent = window.clone();
    let message = format!(
        "{} project {} at version {}. {} workspace(s) may be affected.",
        match summary.operation() {
            ProjectDestructiveOperation::Archive => "Archive",
            ProjectDestructiveOperation::Delete => "Delete",
        },
        summary.project_id(), summary.expected_version(), summary.impacted_workspaces(),
    );
    tauri::async_runtime::spawn_blocking(move || {
        handle.dialog().message(message).title("Confirm destructive action")
            .parent(&parent)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom("Confirm".into(), "Cancel".into()))
            .blocking_show()
    }).await.unwrap_or(false)
}

#[cfg(test)]
async fn native_confirmation(_: &WebviewWindow, summary: DestructiveProjectSummary) -> bool {
    std::future::ready(confirmed_for_test(summary)).await
}

#[cfg(test)]
const fn confirmed_for_test(_: DestructiveProjectSummary) -> bool { true }

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> gocode_app_core::MutationAdmissionBinding {
        gocode_app_core::MutationAdmissionBinding {
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
}
