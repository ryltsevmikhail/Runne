//! macOS containment — blocked by missing Developer ID signing identity.

use super::ContainmentError;

/// Недоступный до появления подписанного helper бэкенд macOS containment.
pub struct MacOsContainment;

impl MacOsContainment {
    /// Сообщить, что production-бэкенд macOS пока недоступен.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Production-бэкенд появится после проверки signed helper с Developer ID.
        Err(ContainmentError::BackendUnavailable)
    }
}
