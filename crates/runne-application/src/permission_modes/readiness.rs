//! Opaque current enforcement readiness and per-invocation native receipts.

use runne_domain::id::IntegrityDigest;

use super::{
    composite::{CompositeScopeDigest, ContainmentStrategy},
    model::{PermissionMode, PresetVersion},
};

/// Why selected mode does not currently have an effective implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyReason {
    /// Required native containment admission is not available.
    NativeContainment,
    /// Managed composite policy cannot be enforced for this scope.
    CompositePolicyUnenforceable,
    /// A versioned preset is unavailable in this runtime.
    PresetUnavailable,
}

/// Effective mode reported independently from the selected mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveModeState {
    /// Selected mode is not backed by an admitted enforcement scope.
    NotReady(NotReadyReason),
    /// The executor supports this preset and capability scope; effects still
    /// require a separate exact invocation admission receipt.
    Ready(EffectiveModeReady),
}

/// App-issued handle binding a native admission token to scope and policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeScopeAdmissionReceipt {
    handle_id: IntegrityDigest,
    scope_digest: CompositeScopeDigest,
    managed_policy_digest: IntegrityDigest,
    containment: ContainmentStrategy,
}

impl NativeScopeAdmissionReceipt {
    pub(super) const fn admitted(
        handle_id: IntegrityDigest,
        scope_digest: CompositeScopeDigest,
        managed_policy_digest: IntegrityDigest,
        containment: ContainmentStrategy,
    ) -> Self {
        Self {
            handle_id,
            scope_digest,
            managed_policy_digest,
            containment,
        }
    }

    /// Opaque key for the executor-owned native token registry.
    pub const fn platform_handle_id(self) -> IntegrityDigest {
        self.handle_id
    }

    /// Exact composite scope admitted by the native executor.
    pub const fn scope_digest(self) -> CompositeScopeDigest {
        self.scope_digest
    }

    /// Managed-policy snapshot enforced by the native executor.
    pub const fn managed_policy_digest(self) -> IntegrityDigest {
        self.managed_policy_digest
    }

    /// Versioned containment strategy admitted by the native executor.
    pub const fn containment(self) -> ContainmentStrategy {
        self.containment
    }
}

/// Opaque current backend-capability readiness evidence, never an effect token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeReadinessReceipt {
    handle_id: IntegrityDigest,
    scope_digest: CompositeScopeDigest,
    managed_policy_digest: IntegrityDigest,
    containment: ContainmentStrategy,
}

impl ModeReadinessReceipt {
    pub(super) const fn checked(
        handle_id: IntegrityDigest,
        scope_digest: CompositeScopeDigest,
        managed_policy_digest: IntegrityDigest,
        containment: ContainmentStrategy,
    ) -> Self {
        Self {
            handle_id,
            scope_digest,
            managed_policy_digest,
            containment,
        }
    }

    /// Opaque readiness registry key; it cannot be used as an effect handle.
    pub const fn platform_handle_id(self) -> IntegrityDigest {
        self.handle_id
    }

    /// Capability scope whose backend support was checked.
    pub const fn scope_digest(self) -> CompositeScopeDigest {
        self.scope_digest
    }

    /// Managed policy snapshot reviewed for readiness.
    pub const fn managed_policy_digest(self) -> IntegrityDigest {
        self.managed_policy_digest
    }

    /// Containment strategy whose implementation support was checked.
    pub const fn containment(self) -> ContainmentStrategy {
        self.containment
    }
}

/// Opaque runtime-created readiness state; it carries no native effect token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveModeReady {
    mode: PermissionMode,
    preset_version: PresetVersion,
    mode_readiness: ModeReadinessReceipt,
}

impl EffectiveModeReady {
    pub(super) const fn admitted(
        mode: PermissionMode,
        preset_version: PresetVersion,
        mode_readiness: ModeReadinessReceipt,
    ) -> Self {
        Self {
            mode,
            preset_version,
            mode_readiness,
        }
    }

    /// Effective mode backed by the runtime-issued admission receipt.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Preset generation admitted for this scope.
    pub const fn preset_version(&self) -> PresetVersion {
        self.preset_version
    }

    /// Read-only backend-readiness evidence; never accepted as launch authority.
    pub const fn mode_readiness(&self) -> ModeReadinessReceipt {
        self.mode_readiness
    }
}
