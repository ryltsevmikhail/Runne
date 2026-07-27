//! Платформенные бэкенды containment: Linux seccomp/Landlock/cgroups,
//! macOS App Sandbox и Windows AppContainer.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod windows;

/// Дескриптор возможностей бэкенда — какие профили поддерживает платформа.
#[derive(Debug, Clone)]
pub struct EnforcementCapabilityDescriptor {
    /// Идентификатор бэкенда containment.
    pub backend_id: String,
    /// Целевая платформа бэкенда.
    pub platform: String,
    /// Версия операционной системы.
    pub os_revision: String,
    /// Поддерживаемые профили enforcement.
    pub supported_profiles: Vec<String>,
    /// Дайджест сертификационных свидетельств.
    pub certification_evidence_digest: String,
}

/// Ошибка применения containment.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ContainmentError {
    /// Бэкенд недоступен на текущей платформе.
    #[error("backend unavailable on this platform")]
    BackendUnavailable,
    /// Запрошенный профиль не поддерживается.
    #[error("profile not supported: {0}")]
    ProfileUnsupported(String),
    /// Не удалось применить sandbox.
    #[error("sandbox apply failed: {0}")]
    SandboxApplyFailed(String),
    /// Ошибка ввода-вывода.
    #[error("io error: {0}")]
    Io(String),
}
