/// Builds sanitized renderer bootstrap state.
///
/// # Errors
///
/// Returns a storage error when settings cannot be queried.
pub fn load_bootstrap(store: &LocalStore) -> Result<BootstrapState, AppCoreError> {
    let theme = match store.get_setting("appearance.theme")? {
        Some(theme) if matches!(theme.as_str(), "dark" | "light") => theme,
        Some(_) => return Err(AppCoreError::InvalidTheme),
        None => "dark".to_owned(),
    };
    Ok(BootstrapState {
        theme,
        runtime_mode: RuntimeMode::ExternalLocal,
        runtime: RuntimeAvailability::Unconfigured,
        runtime_lifecycle: RuntimeLifecycleStatus::External,
        runtime_failure: None,
    })
}
