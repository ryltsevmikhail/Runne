use notify_rust::{Notification, NotificationResponse};
use runne_app_core::{AppCore, CanonicalApprovalState, CanonicalId};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use super::IpcError;
use crate::external_activation::{ActivationEvent, ActivationManager, ActivationTarget};

const NOTIFICATION_TITLE: &str = "Runne";
const NOTIFICATION_BODY: &str = "An approval requires your attention.";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationCategory {
    ApprovalAttention,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationIntent {
    notification_id: String,
    category: NotificationCategory,
    created_at: i64,
}

impl NotificationIntent {
    fn approval(approval_id: &str, created_at: i64) -> Option<Self> {
        if created_at <= 0 || CanonicalId::parse(approval_id).is_err() {
            return None;
        }
        Some(Self {
            notification_id: approval_id.to_owned(),
            category: NotificationCategory::ApprovalAttention,
            created_at,
        })
    }
}

#[derive(Default)]
pub struct NotificationState {
    sent: Mutex<HashSet<String>>,
}

impl NotificationState {
    fn claim(&self, notification_id: &str) -> bool {
        self.sent
            .lock()
            .is_ok_and(|mut sent| sent.insert(notification_id.to_owned()))
    }

    fn forget(&self, notification_id: &str) {
        if let Ok(mut sent) = self.sent.lock() {
            sent.remove(notification_id);
        }
    }

    fn reconcile<I, S>(&self, active: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let active: HashSet<String> = active
            .into_iter()
            .map(|id| id.as_ref().to_owned())
            .collect();
        if let Ok(mut sent) = self.sent.lock() {
            sent.retain(|id| active.contains(id.as_str()));
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSyncResponse {
    shown: u32,
    pending: u32,
}

pub async fn sync_notifications_inner(
    app: &AppHandle,
    core: &Arc<AppCore>,
    state: &NotificationState,
) -> Result<NotificationSyncResponse, IpcError> {
    let approvals = core.list_pending_approvals().await.map_err(|_| IpcError {
        code: "notifications_runtime_unavailable",
    })?;
    let pending_ids = approvals
        .iter()
        .filter(|approval| matches!(approval.state, CanonicalApprovalState::Pending))
        .map(|approval| approval.approval_id.as_str())
        .collect::<Vec<_>>();
    state.reconcile(pending_ids.iter().copied());
    let pending = u32::try_from(pending_ids.len()).unwrap_or(u32::MAX);
    let focused = app
        .get_webview_window("main")
        .and_then(|window| window.is_focused().ok())
        .unwrap_or(false);
    if focused {
        return Ok(NotificationSyncResponse { shown: 0, pending });
    }

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .unwrap_or(1);
    let mut shown = 0u32;
    for approval in approvals
        .iter()
        .filter(|approval| matches!(approval.state, CanonicalApprovalState::Pending))
    {
        let Some(intent) = NotificationIntent::approval(&approval.approval_id, created_at) else {
            continue;
        };
        if !state.claim(&intent.notification_id) {
            continue;
        }
        let notification_id =
            notification_id_from_approval(&intent.notification_id).ok_or(IpcError {
                code: "notification_rejected",
            })?;
        if show_native_approval_notification(app, &intent, notification_id).is_err() {
            state.forget(&intent.notification_id);
            return Err(IpcError {
                code: "notifications_unavailable",
            });
        }
        shown = shown.saturating_add(1);
    }
    Ok(NotificationSyncResponse { shown, pending })
}

fn show_native_approval_notification(
    app: &AppHandle,
    intent: &NotificationIntent,
    notification_id: i32,
) -> Result<(), ()> {
    #[cfg(target_os = "macos")]
    let _ = notify_rust::set_application(&app.config().identifier);

    let mut notification = Notification::new();
    notification
        .summary(NOTIFICATION_TITLE)
        .body(NOTIFICATION_BODY)
        .action("open", "Open Runne")
        .id(u32::try_from(notification_id).map_err(|_| ())?);
    #[cfg(all(unix, not(target_os = "macos")))]
    notification.appname(NOTIFICATION_TITLE);
    #[cfg(windows)]
    notification.app_id(&app.config().identifier);

    let handle = notification.show().map_err(|_| ())?;
    let activation = ActivationTarget {
        runtime: None,
        project_id: None,
        workspace_id: None,
        task_run_id: None,
        approval_id: Some(intent.notification_id.clone()),
        event: Some(ActivationEvent::Approval),
    };
    let activations = app.state::<ActivationManager>().inner().clone();
    let app = app.clone();
    std::thread::Builder::new()
        .name("runne-notification-action".to_owned())
        .spawn(move || {
            let _ = handle.wait_for_response(|response: &NotificationResponse| {
                let should_route = match response {
                    NotificationResponse::Default => true,
                    NotificationResponse::Action(action) => action == "open",
                    NotificationResponse::Reply(_) | NotificationResponse::Closed(_) => false,
                };
                if should_route {
                    activations.forward_target(&app, activation);
                }
            });
        })
        .map_err(|_| ())?;
    Ok(())
}

#[tauri::command]
pub async fn sync_notifications(
    app: AppHandle,
    core: State<'_, Arc<AppCore>>,
    state: State<'_, Arc<NotificationState>>,
) -> Result<NotificationSyncResponse, IpcError> {
    sync_notifications_inner(&app, core.inner(), state.inner().as_ref()).await
}

fn notification_id_from_approval(approval_id: &str) -> Option<i32> {
    let value = Uuid::parse_str(approval_id).ok()?.as_u128();
    let value = i32::try_from(value & 0x7fff_ffff).ok()?;
    (value > 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_intent_contains_only_allowlisted_metadata() {
        let intent = NotificationIntent::approval("018f2e3a-7000-7000-8000-000000000212", 42)
            .expect("valid approval intent");
        assert_eq!(intent.category, NotificationCategory::ApprovalAttention);
        assert_eq!(intent.created_at, 42);
        let value = serde_json::to_value(intent).expect("serializable intent");
        let object = value.as_object().expect("object intent");
        assert_eq!(object.len(), 3);
        assert!(object.contains_key("notificationId"));
        assert!(object.contains_key("category"));
        assert!(object.contains_key("createdAt"));
        assert!(
            !object
                .values()
                .any(|value| value.as_str() == Some("fs:write"))
        );
    }

    #[test]
    fn notification_state_deduplicates_until_reconciled() {
        let state = NotificationState::default();
        assert!(state.claim("approval-1"));
        assert!(!state.claim("approval-1"));
        state.reconcile(["approval-2"]);
        assert!(state.claim("approval-1"));
    }

    #[test]
    fn approval_notification_id_is_bounded_and_stable() {
        let first = notification_id_from_approval("018f2e3a-7000-7000-8000-000000000212")
            .expect("valid id");
        let second = notification_id_from_approval("018f2e3a-7000-7000-8000-000000000212")
            .expect("valid id");
        assert_eq!(first, second);
        assert!(first > 0);
    }

    #[test]
    fn approval_notification_routes_only_to_the_allowlisted_surface() {
        let target = ActivationTarget {
            runtime: None,
            project_id: None,
            workspace_id: None,
            task_run_id: None,
            approval_id: Some("018f2e3a-7000-7000-8000-000000000212".to_owned()),
            event: Some(ActivationEvent::Approval),
        };
        assert!(target.project_id.is_none());
        assert!(target.workspace_id.is_none());
        assert!(target.task_run_id.is_none());
        assert_eq!(target.event, Some(ActivationEvent::Approval));
    }
}
