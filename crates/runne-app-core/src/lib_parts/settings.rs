const DEFAULT_LOCALE: &str = "en";

/// One-field, owner-read appearance acknowledgement safe for the renderer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThemeAcknowledgement {
    pub theme: String,
}

impl AppCore {
    /// Persists a validated theme and returns its exact owner readback.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, storage, or readback failure.
    pub fn set_theme(&self, theme: &str) -> Result<ThemeAcknowledgement, AppCoreError> {
        if !matches!(theme, "dark" | "light") {
            return Err(AppCoreError::InvalidTheme);
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting("appearance.theme", theme)?;
        let readback = store.get_setting("appearance.theme")?;
        drop(store);
        match readback.as_deref() {
            Some(value) if value == theme => Ok(ThemeAcknowledgement {
                theme: value.to_owned(),
            }),
            _ => Err(AppCoreError::InvalidTheme),
        }
    }

    /// Reads the Rust-owned interface locale without exposing local storage.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the store is unavailable or contains an
    /// unsupported locale value.
    pub fn locale(&self) -> Result<String, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        match store.get_setting("appearance.locale")? {
            Some(value) if is_supported_locale(&value) => Ok(value),
            Some(_) => Err(AppCoreError::InvalidLocale),
            None => Ok(DEFAULT_LOCALE.to_owned()),
        }
    }

    /// Persists one of the production interface locales at the owner.
    ///
    /// # Errors
    ///
    /// Returns a closed validation or storage error.
    pub fn set_locale(&self, locale: &str) -> Result<(), AppCoreError> {
        if !is_supported_locale(locale) {
            return Err(AppCoreError::InvalidLocale);
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting("appearance.locale", locale)?;
        drop(store);
        Ok(())
    }
}

fn is_supported_locale(locale: &str) -> bool {
    matches!(locale, "en" | "ru")
}
