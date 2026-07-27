//! In-memory component health registry.

use std::{collections::BTreeMap, sync::RwLock};

use gocode_application::migration::health::{ComponentHealth, HealthComponent, HealthReport};

/// In-memory adapter retaining the latest typed sample per health component.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    samples: RwLock<BTreeMap<HealthComponent, ComponentHealth>>,
}

impl HealthRegistry {
    /// Replace the current sample for one component.
    pub fn record(
        &self,
        component: HealthComponent,
        health: ComponentHealth,
    ) -> Result<(), HealthRegistryError> {
        self.samples
            .write()
            .map_err(|_| HealthRegistryError::Unavailable)?
            .insert(component, health);
        Ok(())
    }

    /// Return a full report; omitted components remain `Unknown`.
    pub fn report(&self) -> Result<HealthReport, HealthRegistryError> {
        let samples = self
            .samples
            .read()
            .map_err(|_| HealthRegistryError::Unavailable)?;
        Ok(HealthReport::from_samples(
            samples
                .iter()
                .map(|(component, health)| (*component, *health)),
        ))
    }
}

/// Closed health-registry adapter failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthRegistryError {
    /// Registry synchronization state is unavailable.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use gocode_application::migration::health::HealthReadinessError;

    use super::*;

    #[test]
    fn missing_component_remains_unknown_in_the_full_report() {
        let registry = HealthRegistry::default();
        registry
            .record(HealthComponent::Store, ComponentHealth::Ready)
            .unwrap();
        let report = registry.report().unwrap();

        assert_eq!(
            report.production_readiness(),
            Err(HealthReadinessError::CriticalUnknown {
                component: HealthComponent::Audit,
            })
        );
        assert_eq!(
            report.get(HealthComponent::TelemetryExport),
            ComponentHealth::Unknown
        );
    }
}
