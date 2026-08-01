/// Starts the native desktop application.
///
/// # Panics
///
/// Panics when Tauri cannot initialize or run the application event loop.
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Destroyed) {
                window
                    .state::<ConversationSubscriptionManager>()
                    .cancel_window(window.label());
            }
        })
        .setup(|app| {
            let profile_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&profile_directory)?;
            let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
            let runtime_mode = select_runtime_mode(std::env::args_os().skip(1))?;
            let core = Arc::new(AppCore::open_with_runtime_mode(
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
                            RuntimeLifecycleManager::bundled(controller)
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
            open_local_project,
            get_diagnostics,
            connect_runtime,
            open_project_conversation,
            resync_project_conversation,
            send_project_message,
            subscribe_project_conversation,
            ack_conversation_update,
            cancel_conversation_subscription
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize GOCODE desktop application");
    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let lifecycle = app.state::<RuntimeLifecycleManager>();
            if lifecycle.begin_explicit_quit() {
                app.state::<ConversationSubscriptionManager>().shutdown();
                lifecycle.stop_owned_runtime();
            }
        }
    });
}
