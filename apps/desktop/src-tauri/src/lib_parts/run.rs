mod provider_selection {
    include!("../provider_selection.rs");
}

include!("page_load.rs");

include!("project_commands.rs");

include!("setup_state.rs");
#[cfg(target_os = "linux")]
include!("linux_enrollment_approval.rs");
#[cfg(target_os = "linux")]
include!("profile_directory_linux.rs");

include!("managed_task_run_handler.rs");

fn handle_window_event(window: &tauri::Window, event: &WindowEvent) {
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            let _ = window.hide();
        }
        WindowEvent::Destroyed => {
            window
                .state::<ConversationSubscriptionManager>()
                .cancel_window(window.label());
            window
                .state::<TaskRunSubscriptionManager>()
                .cancel_window(window.label());
            let _ = window
                .try_state::<DirectorySelectionManager>()
                .and_then(|selections| {
                    selections
                        .renderer_generations()
                        .fence_destroyed(window.label())
                        .ok()
                });
            if let Some(intents) =
                window.try_state::<crate::destructive_intent::DestructiveIntentManager>()
            {
                intents.invalidate_window(window.label());
            }
            if let Some(intents) =
                window.try_state::<crate::destructive_intent::ApprovalIntentManager>()
            {
                intents.invalidate_window(window.label());
            }
            if let Some(intents) = window
                .try_state::<crate::provider_credential_enrollment::CredentialIntentRegistry>(
            ) {
                intents.invalidate_window(window.label());
            }
        }
        _ => {}
    }
}

include!("setup_app.rs");

fn handle_run_event(app: &tauri::AppHandle, event: &RunEvent) {
    if !matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
        return;
    }
    let lifecycle = app.state::<RuntimeLifecycleManager>();
    if !lifecycle.begin_explicit_quit() {
        return;
    }
    app.state::<DirectorySelectionManager>()
        .clear_pending_authority();
    app.state::<crate::destructive_intent::DestructiveIntentManager>()
        .clear_pending();
    app.state::<crate::destructive_intent::ApprovalIntentManager>()
        .clear_pending();
    app.state::<crate::provider_credential_enrollment::CredentialIntentRegistry>()
        .clear_pending();
    app.state::<ConversationSubscriptionManager>().shutdown();
    app.state::<TaskRunSubscriptionManager>().shutdown();
    lifecycle.stop_owned_runtime();
}

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when native desktop initialization or the event loop fails.
#[allow(
    clippy::too_many_lines,
    reason = "the Tauri builder is kept together as one declarative registration list"
)]
pub fn run() {
    run_with_identity(false);
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn run_gui_qualification() {
    run_with_identity(true);
}

#[allow(
    clippy::too_many_lines,
    reason = "the Tauri builder is kept together as one declarative registration list"
)]
fn run_with_identity(gui_qualification: bool) {
    let activations = crate::external_activation::ActivationManager::default();
    let second_instance_activations = activations.clone();
    let (selections, prepared) = directory_managers();
    let destructive_intents = crate::destructive_intent::DestructiveIntentManager::new(
        std::time::Duration::from_secs(30),
    )
    .expect("fixed destructive intent lifetime is valid");
    let approval_intents =
        crate::destructive_intent::ApprovalIntentManager::new(std::time::Duration::from_secs(30))
            .expect("fixed approval intent lifetime is valid");
    let credential_intents = credential_intent_registry();
    let mut builder = tauri::Builder::default()
        .manage(selections)
        .manage(prepared)
        .manage(destructive_intents)
        .manage(approval_intents)
        .manage(credential_intents)
        .manage(activations)
        .plugin(tauri_plugin_dialog::init())
        .on_page_load(|webview, payload| {
            fence_page_load(webview, payload);
            #[cfg(all(target_os = "linux", feature = "test-support"))]
            crate::gui_qualification::on_page_load(webview, payload);
        })
        .on_window_event(handle_window_event)
        .setup(setup_app)
        .invoke_handler(managed_task_run_handler!());
    #[cfg(not(all(target_os = "linux", feature = "test-support")))]
    let _ = gui_qualification;
    #[cfg(not(all(target_os = "linux", feature = "test-support")))]
    let gui_qualification = false;
    if !gui_qualification {
        builder = builder.plugin(tauri_plugin_single_instance::init(
            move |app, args, _cwd| {
                second_instance_activations.forward(app, args);
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            },
        ));
    }
    let context = qualification_context(gui_qualification);
    let app = builder
        .build(context)
        .expect("failed to initialize Runne desktop application");
    app.run(|app, event| handle_run_event(app, &event));
}

fn qualification_context(gui_qualification: bool) -> tauri::Context<tauri::Wry> {
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    if gui_qualification {
        return tauri::generate_context!("tauri.gui-qualification.conf.json");
    }
    let _ = gui_qualification;
    tauri::generate_context!()
}
