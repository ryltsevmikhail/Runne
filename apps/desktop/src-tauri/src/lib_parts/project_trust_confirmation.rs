use runne_app_core::{ProjectTrustControlSnapshotDto, ProjectTrustDecisionDto};
use tauri::{Manager as _, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[derive(Clone, Copy)]
pub enum TrustConfirmationLocale {
    English,
    Russian,
}

pub async fn confirm_trust_change(
    window: &WebviewWindow,
    snapshot: &ProjectTrustControlSnapshotDto,
    action: ProjectTrustDecisionDto,
    locale: TrustConfirmationLocale,
) -> bool {
    let handle = window.app_handle().clone();
    let parent = window.clone();
    let (title, message, confirm, cancel) = copy(snapshot, action, locale);
    tauri::async_runtime::spawn_blocking(move || {
        handle
            .dialog()
            .message(message)
            .title(title)
            .parent(&parent)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(confirm, cancel))
            .blocking_show()
    })
    .await
    .unwrap_or(false)
}

fn copy(
    snapshot: &ProjectTrustControlSnapshotDto,
    action: ProjectTrustDecisionDto,
    locale: TrustConfirmationLocale,
) -> (String, String, String, String) {
    let (title, yes, no) = match (locale, action) {
        (TrustConfirmationLocale::English, ProjectTrustDecisionDto::ConfirmProject) => {
            ("Trust this project?", "Trust project", "Cancel")
        }
        (TrustConfirmationLocale::English, ProjectTrustDecisionDto::RevokeProject) => {
            ("Revoke project trust?", "Revoke trust", "Cancel")
        }
        (TrustConfirmationLocale::Russian, ProjectTrustDecisionDto::ConfirmProject) => {
            ("Доверять этому проекту?", "Доверять проекту", "Отмена")
        }
        (TrustConfirmationLocale::Russian, ProjectTrustDecisionDto::RevokeProject) => {
            ("Отозвать доверие к проекту?", "Отозвать доверие", "Отмена")
        }
    };
    let reference = snapshot.project_id().to_string();
    let short = &reference[reference.len().saturating_sub(8)..];
    let message = match locale {
        TrustConfirmationLocale::English => format!(
            "Project: “{}”\nScope: this project and all its attached folders.\nWorkspace: “{}”\nProject ref: …{short}",
            snapshot.project_name(),
            snapshot.workspace_name()
        ),
        TrustConfirmationLocale::Russian => format!(
            "Проект: «{}»\nОбласть доверия: проект и все подключённые к нему папки.\nРабочая область: «{}»\nИдентификатор проекта: …{short}",
            snapshot.project_name(),
            snapshot.workspace_name()
        ),
    };
    (title.to_owned(), message, yes.to_owned(), no.to_owned())
}
