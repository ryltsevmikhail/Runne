use super::{NativeConfirmationLocale, ProjectDestructiveOperation};
use runne_app_core::DestructiveProjectSummary;
#[cfg(not(test))]
use tauri::Manager;
#[cfg(not(test))]
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[cfg(not(test))]
pub async fn native_confirmation(
    window: &super::WebviewWindow,
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

#[cfg(test)]
pub async fn native_confirmation(
    _: &super::WebviewWindow,
    _: DestructiveProjectSummary,
    _: NativeConfirmationLocale,
) -> bool {
    true
}

pub fn confirmation_copy(
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
            (
                title,
                action,
                "Подтвердить",
                "Отмена",
                impact,
                "Код проекта",
            )
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
