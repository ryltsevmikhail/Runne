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
        if let Some(intents) = webview
            .try_state::<crate::destructive_intent::DestructiveIntentManager>()
        {
            intents.invalidate_window(webview.label());
        }
    }
}

/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when native desktop initialization or the event loop fails.
#[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
pub fn run() {
    let selections = DirectorySelectionManager::new(std::time::Duration::from_secs(30))
        .expect("fixed directory selection lifetime is valid");
    let prepared = selections.prepared_workspaces();
    let destructive_intents = crate::destructive_intent::DestructiveIntentManager::new(
        std::time::Duration::from_secs(30),
    ).expect("fixed destructive intent lifetime is valid");
    let app = tauri::Builder::default()
        .manage(selections)
        .manage(prepared)
        .manage(destructive_intents)
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .on_page_load(fence_page_load)
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Destroyed) {
                window
                    .state::<ConversationSubscriptionManager>()
                    .cancel_window(window.label());
                let _ = window
                    .try_state::<DirectorySelectionManager>()
                        .and_then(|selections| {
                        selections
                            .renderer_generations()
                            .fence_destroyed(window.label())
                            .ok()
                    });
                if let Some(intents) = window
                    .try_state::<crate::destructive_intent::DestructiveIntentManager>()
                {
                    intents.invalidate_window(window.label());
                }
            }
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
            app.manage(profile_lock);
            app.manage(core);
            app.manage(ConversationSubscriptionManager::new());
            app.manage(lifecycle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_bootstrap,
            set_theme,
            list_projects,
            get_project,
            get_workspace,
            acquire_renderer_generation,
            request_directory_selection,
            prepare_selected_workspace,
            open_selected_workspace,
            retry_open_selected_workspace,
            prepare_destructive_project_action,
            dispatch_destructive_project_action,
            get_diagnostics,
            connect_runtime,
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize GOCODE desktop application");
    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let lifecycle = app.state::<RuntimeLifecycleManager>();
            if lifecycle.begin_explicit_quit() {
                app.state::<DirectorySelectionManager>()
                    .clear_pending_authority();
                app.state::<crate::destructive_intent::DestructiveIntentManager>()
                    .clear_pending();
                app.state::<ConversationSubscriptionManager>().shutdown();
                lifecycle.stop_owned_runtime();
            }
        }
    });
}
