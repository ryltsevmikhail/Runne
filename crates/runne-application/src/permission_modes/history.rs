//! Codec-friendly snapshots that never reconstruct runtime authority.

use super::{
    composite::{CompositeScopeDigest, ContainmentStrategy},
    model::{NetworkState, PermissionMode, PermissionModeProjection, PresetVersion},
    readiness::{EffectiveModeState, NotReadyReason},
};

/// Non-authoritative durable snapshot that can be decoded without restoring a
/// native admission token. A historical `Ready` value is never compiler input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionModeHistoryProjection {
    /// Mode selected when the durable command committed.
    pub selected_mode: PermissionMode,
    /// Readable snapshot of effective state at commit time only.
    pub effective: EffectiveModeHistoryState,
    /// Authorization revision committed by the command.
    pub authorization_revision: u64,
    /// Preset generation used for the receipt.
    pub preset_version: PresetVersion,
    /// Managed-policy generation checked for the command.
    pub managed_policy_version: u64,
    /// Current containment observation at commit time.
    pub containment: Option<ContainmentStrategy>,
    /// Network posture observed at commit time.
    pub network_state: NetworkState,
    /// Selection expiry, distinct from challenge expiry.
    pub expires_at_unix_ms: Option<i64>,
}

/// Read-only historic effective-mode observation with no launch authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveModeHistoryState {
    /// No admitted enforcement was reported at command completion.
    NotReady(NotReadyReason),
    /// Native admission existed at command completion; this summary is not
    /// itself an admission receipt and cannot authorize a later invocation.
    Ready {
        /// Mode admitted at command completion.
        mode: PermissionMode,
        /// Preset generation admitted at command completion.
        preset_version: PresetVersion,
        /// Scope that was admitted at command completion.
        scope_digest: CompositeScopeDigest,
        /// Containment strategy reported at command completion.
        containment: ContainmentStrategy,
    },
}

impl PermissionModeProjection {
    /// Copy this current runtime projection into a non-authoritative durable summary.
    pub fn history_snapshot(&self) -> PermissionModeHistoryProjection {
        let effective = match &self.effective {
            EffectiveModeState::NotReady(reason) => EffectiveModeHistoryState::NotReady(*reason),
            EffectiveModeState::Ready(ready) => {
                let readiness = ready.mode_readiness();
                EffectiveModeHistoryState::Ready {
                    mode: ready.mode(),
                    preset_version: ready.preset_version(),
                    scope_digest: readiness.scope_digest(),
                    containment: readiness.containment(),
                }
            }
        };
        PermissionModeHistoryProjection {
            selected_mode: self.selected_mode,
            effective,
            authorization_revision: self.authorization_revision,
            preset_version: self.preset_version,
            managed_policy_version: self.managed_policy_version,
            containment: self.containment,
            network_state: self.network_state,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }
}
