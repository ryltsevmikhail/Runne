const DEFAULT_COMMAND_PALETTE: &str = "Ctrl+Shift+P";
const DEFAULT_OPEN_PROJECT: &str = "Ctrl+O";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ShortcutSettings {
    pub command_palette: String,
    pub open_project: String,
}

impl Default for ShortcutSettings {
    fn default() -> Self {
        Self {
            command_palette: DEFAULT_COMMAND_PALETTE.to_owned(),
            open_project: DEFAULT_OPEN_PROJECT.to_owned(),
        }
    }
}

impl ShortcutSettings {
    /// Builds a validated pair of user-facing shortcut bindings.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or conflicting bindings.
    pub fn new(command_palette: &str, open_project: &str) -> Result<Self, AppCoreError> {
        let value = Self {
            command_palette: command_palette.to_owned(),
            open_project: open_project.to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), AppCoreError> {
        if !valid_binding(&self.command_palette)
            || !valid_binding(&self.open_project)
            || self.command_palette == self.open_project
        {
            return Err(AppCoreError::InvalidShortcuts);
        }
        Ok(())
    }
}

impl AppCore {
    /// Reads the owner-persisted keyboard shortcuts.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed stored settings or storage failure.
    pub fn shortcuts(&self) -> Result<ShortcutSettings, AppCoreError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        let Some(value) = store.get_setting("settings.shortcuts")? else {
            return Ok(ShortcutSettings::default());
        };
        let shortcuts = serde_json::from_str::<ShortcutSettings>(&value)
            .map_err(|_| AppCoreError::InvalidShortcuts)?;
        shortcuts.validate()?;
        drop(store);
        Ok(shortcuts)
    }

    /// Persists validated keyboard shortcuts at the desktop owner.
    ///
    /// # Errors
    ///
    /// Returns a closed validation or storage error.
    pub fn set_shortcuts(&self, shortcuts: &ShortcutSettings) -> Result<(), AppCoreError> {
        shortcuts.validate()?;
        let value = serde_json::to_string(&shortcuts).map_err(|_| AppCoreError::InvalidShortcuts)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AppCoreError::StateUnavailable)?;
        store.set_setting("settings.shortcuts", &value)?;
        drop(store);
        Ok(())
    }
}

fn valid_binding(binding: &str) -> bool {
    let parts: Vec<&str> = binding.split('+').collect();
    let modifiers = &parts[..parts.len().saturating_sub(1)];
    (2..=4).contains(&parts.len())
        && modifiers
            .iter()
            .all(|part| matches!(*part, "Ctrl" | "Alt" | "Shift" | "Meta"))
        && modifiers
            .iter()
            .enumerate()
            .all(|(index, part)| !modifiers[..index].contains(part))
        && parts.last().is_some_and(|key| {
            (key.len() == 1 && key.as_bytes()[0].is_ascii_alphanumeric())
                || (key.starts_with('F') && (2..=3).contains(&key.len()) && key[1..].chars().all(|c| c.is_ascii_digit()))
        })
}
