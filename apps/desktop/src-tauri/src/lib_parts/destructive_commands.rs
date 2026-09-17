use runne_app_core::{
    DestructiveConfirmationContext, DestructiveConfirmationLease,
    DestructiveConfirmationFuture, DestructiveConfirmationPort,
    ProjectDestructiveOperation,
};
use serde::Deserialize;

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

#[path = "destructive_commands/confirmation.rs"]
mod confirmation;
use confirmation::native_confirmation;

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

#[cfg(test)]
#[path = "destructive_commands/tests.rs"]
mod tests;
