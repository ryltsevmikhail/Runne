fn setup_app(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let profile_directory = app.path().app_data_dir()?;
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let gui_qualification = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_stem().map(|name| name == "d2-gui-qualification"))
        .unwrap_or(false);
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let profile_directory = if gui_qualification {
        profile_directory.join("d2-gui-qualification")
    } else {
        profile_directory
    };
    #[cfg(target_os = "linux")]
    ensure_linux_profile_directory_private(&profile_directory)?;
    #[cfg(not(target_os = "linux"))]
    std::fs::create_dir_all(&profile_directory)?;
    app.manage(crate::LocalModelState::new(
        profile_directory.join("local-engine").join("models"),
    ));
    let profile_lock = ProfileLock::acquire(&profile_directory.join("profile.lock"))?;
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let provider_selection =
        crate::provider_selection::provider_selection(arguments.iter().cloned())?;
    #[cfg(target_os = "linux")]
    let approve_linux_enrollment = linux_enrollment_approval_requested(&arguments)?;
    let runtime_mode = select_runtime_mode(arguments.iter().cloned())?;
    if provider_selection.is_explicit() && runtime_mode != RuntimeMode::Bundled {
        return Err("provider selection requires bundled runtime".into());
    }
    #[cfg(target_os = "linux")]
    if approve_linux_enrollment && runtime_mode != RuntimeMode::Bundled {
        return Err("activation requires bundled runtime".into());
    }
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let gui_qualification = if gui_qualification {
        Some(
            crate::gui_qualification::GuiQualificationControl::from_env()
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let core = Arc::new(if let Some(control) = gui_qualification.as_ref() {
        control.open_core(&profile_directory)?
    } else {
        AppCore::open_production(&profile_directory.join("profile.sqlite3"), runtime_mode)?
    });
    #[cfg(not(all(target_os = "linux", feature = "test-support")))]
    let core = Arc::new(AppCore::open_production(
        &profile_directory.join("profile.sqlite3"),
        runtime_mode,
    )?);
    let mut monitor = install_runtime_lifecycle(
        app,
        &core,
        &profile_directory,
        runtime_mode,
        &provider_selection,
    )?;
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
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    if let Some(control) = gui_qualification {
        app.manage(control);
    }
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
    #[cfg(target_os = "linux")]
    if approve_linux_enrollment {
        start_linux_enrollment_approval(app.handle().clone());
    }
    if let Some(controller) = monitor.take() {
        controller.spawn_monitor(app.handle().clone());
    }
    drop(monitor);
    tray::install(app.handle())?;
    start_notification_sync(app, notification_core, notification_state);
    Ok(())
}

fn start_notification_sync(
    app: &tauri::App,
    core: Arc<AppCore>,
    state: Arc<crate::notifications::NotificationState>,
) {
    let notification_app = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if notification_app.get_webview_window("main").is_none() {
                break;
            }
            let _ = crate::notifications::sync_notifications_inner(
                &notification_app,
                &core,
                state.as_ref(),
            )
            .await;
        }
    });
}

fn install_runtime_lifecycle(
    app: &tauri::App,
    core: &Arc<AppCore>,
    profile_directory: &std::path::Path,
    runtime_mode: RuntimeMode,
    selection: &provider_selection::ProviderSelection,
) -> Result<Option<Arc<crate::bundled_runtime::BundledRuntimeController>>, Box<dyn std::error::Error>>
{
    let mut monitor = None;
    let lifecycle = match runtime_mode {
        RuntimeMode::ExternalLocal => RuntimeLifecycleManager::external(),
        RuntimeMode::Bundled => match std::env::current_exe()
            .map_err(|_| RuntimeFailureCode::BundledExecutableUnavailable)
            .and_then(|executable| {
                BundledRuntimeController::discover_with_provider_activation(
                    Arc::clone(core),
                    &executable,
                    &profile_directory.join("bundled-runtime"),
                    selection.binding(),
                )
            }) {
            Ok(controller) => {
                #[cfg(target_os = "linux")]
                crate::provider_credential_enrollment::linux_activation::install_managed_context(
                    &controller,
                );
                monitor = Some(Arc::clone(&controller));
                RuntimeLifecycleManager::bundled_with_native_root(controller)
            }
            Err(failure) => {
                tauri::async_runtime::block_on(core.mark_bundled_runtime_failed(failure))?;
                RuntimeLifecycleManager::bundled_unavailable()
            }
        },
    };
    app.manage(lifecycle);
    Ok(monitor)
}
