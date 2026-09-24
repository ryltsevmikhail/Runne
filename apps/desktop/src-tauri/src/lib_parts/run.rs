include!("page_load.rs");

include!("project_commands.rs");

include!("setup_state.rs");

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

fn setup_app(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let profile_directory = app.path().app_data_dir()?;
    app.manage(crate::LocalModelState::new(
        profile_directory.join("local-engine").join("models"),
    ));
    std::fs::create_dir_all(&profile_directory)?;
    let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
    let runtime_mode = select_runtime_mode(std::env::args_os().skip(1))?;
    let core = Arc::new(AppCore::open_production(
        &profile_directory.join("profile.sqlite3"),
        runtime_mode,
    )?);
    let mut monitor = None;
    let lifecycle = match runtime_mode {
        RuntimeMode::ExternalLocal => RuntimeLifecycleManager::external(),
        RuntimeMode::Bundled => match std::env::current_exe()
            .map_err(|_| RuntimeFailureCode::BundledExecutableUnavailable)
            .and_then(|executable| {
                BundledRuntimeController::discover(
                    Arc::clone(&core),
                    &executable,
                    &profile_directory.join("bundled-runtime"),
                )
            }) {
            Ok(controller) => {
                #[cfg(target_os = "linux")]
                crate::provider_credential_enrollment::linux_activation::install_managed_context(&controller);
                monitor = Some(Arc::clone(&controller));
                RuntimeLifecycleManager::bundled_with_native_root(controller)
            }
            Err(failure) => {
                tauri::async_runtime::block_on(core.mark_bundled_runtime_failed(failure))?;
                RuntimeLifecycleManager::bundled_unavailable()
            }
        },
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let qualification_admission =
        crate::bundled_runtime::qualification_ticket::admit_inherited_qualification_admission(
            monitor
                .as_deref()
                .map(BundledRuntimeController::qualification_admission),
        )?;
    let notification_core = Arc::clone(&core);
    let notification_state = Arc::new(crate::notifications::NotificationState::default());
    app.manage(profile_lock);
    app.manage(core);
    app.manage(crate::updater_status::UpdateStatusStore::new(
        &profile_directory.join("bundled-runtime"),
    ));
    let _ = app
        .state::<crate::updater_status::UpdateStatusStore>()
        .begin_health_check_if_required();
    app.manage(Arc::clone(&notification_state));
    app.state::<crate::external_activation::ActivationManager>()
        .forward(app.handle(), std::env::args_os().skip(1));
    app.manage(ConversationSubscriptionManager::new());
    app.manage(TaskRunSubscriptionManager::new());
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    app.manage(qualification_admission);
    app.manage(lifecycle);
    if let Some(controller) = monitor.take() {
        controller.spawn_monitor(app.handle().clone());
    }
    drop(monitor);
    tray::install(app.handle())?;
    let notification_app = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if notification_app.get_webview_window("main").is_none() {
                break;
            }
            let _ = crate::notifications::sync_notifications_inner(
                &notification_app,
                &notification_core,
                notification_state.as_ref(),
            )
            .await;
        }
    });
    Ok(())
}

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
    let app = tauri::Builder::default()
        .manage(selections)
        .manage(prepared)
        .manage(destructive_intents)
        .manage(approval_intents)
        .manage(credential_intents)
        .manage(activations)
        .plugin(tauri_plugin_single_instance::init(
            move |app, args, _cwd| {
                second_instance_activations.forward(app, args);
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            },
        ))
        .plugin(tauri_plugin_dialog::init())
        .on_page_load(fence_page_load)
        .on_window_event(handle_window_event)
        .setup(setup_app)
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            set_theme,
            get_locale,
            set_locale,
            get_shortcuts,
            set_shortcuts,
            get_device_status,
            get_provider_status,
            get_provider_quota,
            get_provider_catalog,
            local_model_stage,
            local_model_admit,
            local_model_list,
            local_model_discard,
            get_provider_credential_enrollment_status,
            request_provider_credential_intent,
            get_update_status,
            check_update,
            download_update,
            prepare_update_install,
            crate::notifications::sync_notifications,
            list_projects,
            list_canonical_projects,
            create_runtime_project,
            create_runtime_workspace,
            open_runtime_workspace,
            get_project,
            get_canonical_project,
            rename_runtime_project,
            get_workspace,
            get_canonical_workspace,
            list_workspace_files,
            read_workspace_file,
            list_workspace_changes,
            read_workspace_diff,
            start_process,
            get_process,
            read_process_output,
            stop_process,
            open_workspace_editor,
            get_task_run_timeline,
            list_pending_approvals,
            get_approval,
            prepare_approval_decision,
            consume_approval_decision,
            resync_task_run_timeline,
            cancel_task_run,
            submit_task_run,
            subscribe_task_run_timeline,
            ack_task_run_update,
            cancel_task_run_subscription,
            open_workspace_conversation,
            resync_workspace_conversation,
            send_workspace_message,
            subscribe_workspace_conversation,
            ack_conversation_update,
            cancel_conversation_subscription,
            acquire_renderer_generation,
            request_directory_selection,
            prepare_selected_workspace,
            open_selected_workspace,
            retry_open_selected_workspace,
            prepare_destructive_project_action,
            dispatch_destructive_project_action,
            get_diagnostics,
            diagnostics_export::get_diagnostics_export_preview,
            diagnostics_export::export_diagnostics,
            operational_telemetry_command::get_operational_telemetry,
            connect_runtime,
            get_pending_external_activation,
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize Runne desktop application");
    app.run(|app, event| handle_run_event(app, &event));
}
