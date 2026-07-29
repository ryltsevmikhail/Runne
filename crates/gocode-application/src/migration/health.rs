//! Component-scoped health contracts for migration production gates.

use std::collections::BTreeMap;

/// Closed component inventory used by production-readiness evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthComponent {
    /// Durable canonical store.
    Store,
    /// Canonical audit commit and replay.
    Audit,
    /// Security-policy authority.
    Security,
    /// Exact platform containment.
    Platform,
    /// Runtime ingress, workers and supervisor.
    Runtime,
    /// Restart, replay and uncertain-effect recovery.
    Recovery,
    /// Optional external telemetry exporter.
    TelemetryExport,
}

impl HealthComponent {
    /// Every component in stable report order.
    pub const ALL: [Self; 7] = [
        Self::Store,
        Self::Audit,
        Self::Security,
        Self::Platform,
        Self::Runtime,
        Self::Recovery,
        Self::TelemetryExport,
    ];

    /// Components whose non-ready status blocks production eligibility.
    pub const CRITICAL: [Self; 6] = [
        Self::Store,
        Self::Audit,
        Self::Security,
        Self::Platform,
        Self::Runtime,
        Self::Recovery,
    ];
}

/// Closed, privacy-safe health reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthCode {
    /// Canonical store is unavailable or unhealthy.
    StoreUnavailable,
    /// Canonical audit is unavailable or unhealthy.
    AuditUnavailable,
    /// Security policy is unavailable or denied readiness.
    SecurityUnavailable,
    /// Exact platform tuple is not certified.
    PlatformUncertified,
    /// Runtime ingress or workers are unavailable.
    RuntimeUnavailable,
    /// Recovery evidence is unavailable.
    RecoveryUnavailable,
    /// Optional telemetry exporter cannot currently export.
    ExporterUnavailable,
}

/// Current health of one exact component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentHealth {
    /// Component satisfies its readiness contract.
    Ready,
    /// Component is operating with a typed degradation.
    Degraded {
        /// Machine-distinguishable degradation.
        code: HealthCode,
    },
    /// Component is explicitly blocked.
    Blocked {
        /// Machine-distinguishable blocking reason.
        code: HealthCode,
    },
    /// No current trustworthy sample exists.
    Unknown,
}

/// Complete component-scoped health report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    components: BTreeMap<HealthComponent, ComponentHealth>,
}

impl HealthReport {
    /// Construct a report whose every known component is ready.
    pub fn all_ready() -> Self {
        Self::from_samples(
            HealthComponent::ALL
                .into_iter()
                .map(|component| (component, ComponentHealth::Ready)),
        )
    }

    /// Construct a report from current samples; omitted components stay unknown.
    pub fn from_samples(
        samples: impl IntoIterator<Item = (HealthComponent, ComponentHealth)>,
    ) -> Self {
        Self {
            components: samples.into_iter().collect(),
        }
    }

    /// Return a copy with one component sample replaced.
    pub fn with(mut self, component: HealthComponent, health: ComponentHealth) -> Self {
        self.components.insert(component, health);
        self
    }

    /// Return one component sample, preserving absence as `Unknown`.
    pub fn get(&self, component: HealthComponent) -> ComponentHealth {
        self.components
            .get(&component)
            .copied()
            .unwrap_or(ComponentHealth::Unknown)
    }

    /// Return the complete explicitly recorded component map.
    pub fn components(&self) -> &BTreeMap<HealthComponent, ComponentHealth> {
        &self.components
    }

    /// Evaluate production readiness without flattening component state.
    pub fn production_readiness(&self) -> Result<(), HealthReadinessError> {
        for component in HealthComponent::CRITICAL {
            match self.get(component) {
                ComponentHealth::Ready => {}
                ComponentHealth::Unknown => {
                    return Err(HealthReadinessError::CriticalUnknown { component });
                }
                ComponentHealth::Degraded { code } => {
                    return Err(HealthReadinessError::CriticalDegraded { component, code });
                }
                ComponentHealth::Blocked { code } => {
                    return Err(HealthReadinessError::CriticalBlocked { component, code });
                }
            }
        }
        Ok(())
    }
}

/// Typed production-readiness failure that retains component identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthReadinessError {
    /// A critical component has no trustworthy current sample.
    CriticalUnknown {
        /// Missing critical component.
        component: HealthComponent,
    },
    /// A critical component is degraded.
    CriticalDegraded {
        /// Degraded critical component.
        component: HealthComponent,
        /// Typed degradation code.
        code: HealthCode,
    },
    /// A critical component is blocked.
    CriticalBlocked {
        /// Blocked critical component.
        component: HealthComponent,
        /// Typed blocking code.
        code: HealthCode,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_critical_component_blocks_gate_readiness() {
        let report =
            HealthReport::all_ready().with(HealthComponent::Audit, ComponentHealth::Unknown);
        assert_eq!(
            report.production_readiness(),
            Err(HealthReadinessError::CriticalUnknown {
                component: HealthComponent::Audit,
            })
        );
    }

    #[test]
    fn exporter_outage_is_degraded_when_canonical_audit_is_ready() {
        let report = HealthReport::all_ready().with(
            HealthComponent::TelemetryExport,
            ComponentHealth::Degraded {
                code: HealthCode::ExporterUnavailable,
            },
        );
        assert_eq!(report.production_readiness(), Ok(()));
        assert!(matches!(
            report.get(HealthComponent::TelemetryExport),
            ComponentHealth::Degraded { .. }
        ));
    }

    #[test]
    fn exporter_readiness_cannot_replace_unavailable_canonical_audit() {
        let report = HealthReport::all_ready().with(
            HealthComponent::Audit,
            ComponentHealth::Blocked {
                code: HealthCode::AuditUnavailable,
            },
        );
        let before = report.clone();

        assert_eq!(
            report.production_readiness(),
            Err(HealthReadinessError::CriticalBlocked {
                component: HealthComponent::Audit,
                code: HealthCode::AuditUnavailable,
            })
        );
        assert_eq!(report, before);
        assert_eq!(
            report.get(HealthComponent::TelemetryExport),
            ComponentHealth::Ready
        );
    }

    #[test]
    fn critical_store_and_audit_health_is_not_flattened() {
        let report = HealthReport::all_ready()
            .with(
                HealthComponent::Store,
                ComponentHealth::Degraded {
                    code: HealthCode::StoreUnavailable,
                },
            )
            .with(
                HealthComponent::Audit,
                ComponentHealth::Blocked {
                    code: HealthCode::AuditUnavailable,
                },
            );
        let before = report.clone();

        assert_eq!(
            report.production_readiness(),
            Err(HealthReadinessError::CriticalDegraded {
                component: HealthComponent::Store,
                code: HealthCode::StoreUnavailable,
            })
        );
        assert_eq!(report, before);
        assert_eq!(
            report.get(HealthComponent::Store),
            ComponentHealth::Degraded {
                code: HealthCode::StoreUnavailable,
            }
        );
        assert_eq!(
            report.get(HealthComponent::Audit),
            ComponentHealth::Blocked {
                code: HealthCode::AuditUnavailable,
            }
        );
    }
}
