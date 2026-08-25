fn fence_page_load<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    payload: &tauri::webview::PageLoadPayload<'_>,
) {
    if matches!(payload.event(), tauri::webview::PageLoadEvent::Started) {
        let _ = webview
            .try_state::<DirectorySelectionManager>()
            .ok_or(())
            .and_then(|selections| {
                selections
                    .renderer_generations()
                    .page_loaded(webview.label())
                    .map_err(|_| ())
            });
        if let Some(intents) =
            webview.try_state::<crate::destructive_intent::DestructiveIntentManager>()
        {
            intents.invalidate_window(webview.label());
        }
    }
}

include!("project_commands.rs");

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when native desktop initialization or the event loop fails.
#[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
pub fn run() {
    let activations = crate::external_activation::ActivationManager::default();
    let second_instance_activations = activations.clone();
    let selections = DirectorySelectionManager::new(std::time::Duration::from_secs(30))
        .expect("fixed directory selection lifetime is valid");
    let prepared = selections.prepared_workspaces();
    let destructive_intents = crate::destructive_intent::DestructiveIntentManager::new(
        std::time::Duration::from_secs(30),
    )
    .expect("fixed destructive intent lifetime is valid");
    let app = tauri::Builder::default()
        .manage(selections)
        .manage(prepared)
        .manage(destructive_intents)
        .manage(activations)
        .plugin(tauri_plugin_single_instance::init(move |app, args, _cwd| {
            second_instance_activations.forward(app, args);
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .on_page_load(fence_page_load)
        .on_window_event(|window, event| match event {
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
            }
            _ => {}
        })
        .setup(|app| {
            let profile_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&profile_directory)?;
            let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
            let runtime_mode = select_runtime_mode(std::env::args_os().skip(1))?;
            let core = Arc::new(AppCore::open_production(
                &profile_directory.join("profile.sqlite3"),
                runtime_mode,
            )?);
            let lifecycle = match runtime_mode {
                RuntimeMode::ExternalLocal => RuntimeLifecycleManager::external(),
                RuntimeMode::Bundled => {
                    let controller = std::env::current_exe()
                        .map_err(|_| RuntimeFailureCode::BundledExecutableUnavailable)
                        .and_then(|desktop_executable| {
                            BundledRuntimeController::discover(
                                Arc::clone(&core),
                                &desktop_executable,
                                &profile_directory.join("bundled-runtime"),
                            )
                        });
                    match controller {
                        Ok(controller) => {
                            controller.spawn_monitor();
                            RuntimeLifecycleManager::bundled_with_native_root(controller)
                        }
                        Err(failure) => {
                            tauri::async_runtime::block_on(
                                core.mark_bundled_runtime_failed(failure),
                            )?;
                            RuntimeLifecycleManager::bundled_unavailable()
                        }
                    }
                }
            };
            let notification_core = Arc::clone(&core);
            let notification_state = Arc::new(crate::notifications::NotificationState::default());
            app.manage(profile_lock);
            app.manage(core);
            app.manage(crate::updater_status::UpdateStatusStore::new(&profile_directory));
            let _ = app
                .state::<crate::updater_status::UpdateStatusStore>()
                .begin_health_check_if_required();
            app.manage(Arc::clone(&notification_state));
            app.state::<crate::external_activation::ActivationManager>()
                .forward(app.handle(), std::env::args_os().skip(1));
            app.manage(ConversationSubscriptionManager::new());
            app.manage(TaskRunSubscriptionManager::new());
            app.manage(lifecycle);
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
        })
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            set_theme,
            get_locale,
            set_locale,
            get_shortcuts,
            set_shortcuts,
        get_device_status,
            get_provider_status,
            pair_provider_credential,
            revoke_provider_credential,
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
            respond_to_approval,
            resync_task_run_timeline,
            cancel_task_run,
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
    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let lifecycle = app.state::<RuntimeLifecycleManager>();
            if lifecycle.begin_explicit_quit() {
                app.state::<DirectorySelectionManager>()
                    .clear_pending_authority();
                app.state::<crate::destructive_intent::DestructiveIntentManager>()
                    .clear_pending();
                app.state::<ConversationSubscriptionManager>().shutdown();
                app.state::<TaskRunSubscriptionManager>().shutdown();
                lifecycle.stop_owned_runtime();
            }
        }
    });
}
