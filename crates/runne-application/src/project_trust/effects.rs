use super::ProjectTrustRecord;

/// Version of the closed six-class managed effect policy.
pub const MANAGED_EFFECT_POLICY_VERSION: u32 = 1;

/// Closed effect classes represented by managed project policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagedEffectClass {
    /// Read filesystem content.
    FsRead,
    /// Create filesystem entries.
    FsCreate,
    /// Modify filesystem content.
    FsWrite,
    /// Remove filesystem entries.
    FsDelete,
    /// Start a process.
    ProcessStart,
    /// Use network access.
    NetworkUse,
}

impl ManagedEffectClass {
    /// Canonical order for persistence and digest encoding.
    pub const ALL: [Self; 6] = [
        Self::FsRead,
        Self::FsCreate,
        Self::FsWrite,
        Self::FsDelete,
        Self::ProcessStart,
        Self::NetworkUse,
    ];

    /// Stable class tag for canonical encoding.
    pub const fn tag(self) -> u8 {
        match self {
            Self::FsRead => 1,
            Self::FsCreate => 2,
            Self::FsWrite => 3,
            Self::FsDelete => 4,
            Self::ProcessStart => 5,
            Self::NetworkUse => 6,
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.tag() as usize - 1
    }
}

/// Managed overlay decision for one effect class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagedEffectDecision {
    /// Adds no restriction beyond existing gates and presets.
    Allow,
    /// Requires an explicit approval at the consuming boundary.
    Ask,
    /// Rejects the effect regardless of a preset.
    Deny,
}

impl ManagedEffectDecision {
    /// Stable database code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Ask => 1,
            Self::Deny => 2,
        }
    }

    /// Parses only the three defined database codes.
    pub const fn from_code(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Allow),
            1 => Some(Self::Ask),
            2 => Some(Self::Deny),
            _ => None,
        }
    }

    /// Stable decision tag for canonical encoding.
    pub const fn tag(self) -> u8 {
        self.code() + 1
    }
}

/// Versioned ordered rules for the six managed effect classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedEffectPolicyV1 {
    /// Persisted version; unknown values are invalid and compile to deny.
    pub version: u32,
    decisions: [ManagedEffectDecision; 6],
}

impl ManagedEffectPolicyV1 {
    /// Builds a policy from decisions in [`ManagedEffectClass::ALL`] order.
    pub const fn new(version: u32, decisions: [ManagedEffectDecision; 6]) -> Self {
        Self { version, decisions }
    }

    /// Legacy-compatible policy allowing all six managed classes.
    pub const fn all_allow() -> Self {
        Self::new(
            MANAGED_EFFECT_POLICY_VERSION,
            [ManagedEffectDecision::Allow; 6],
        )
    }

    /// Replaces one closed class decision.
    pub const fn with_decision(
        mut self,
        class: ManagedEffectClass,
        decision: ManagedEffectDecision,
    ) -> Self {
        self.decisions[class.index()] = decision;
        self
    }

    /// Returns a class decision from the canonical fixed mapping.
    pub const fn decision_for(self, class: ManagedEffectClass) -> ManagedEffectDecision {
        self.decisions[class.index()]
    }

    /// Returns decisions in the canonical order.
    pub const fn decisions(self) -> [ManagedEffectDecision; 6] {
        self.decisions
    }

    /// Whether the policy is the legacy all-allow value.
    pub const fn is_all_allow(self) -> bool {
        self.version == MANAGED_EFFECT_POLICY_VERSION
            && matches!(
                self.decisions,
                [
                    ManagedEffectDecision::Allow,
                    ManagedEffectDecision::Allow,
                    ManagedEffectDecision::Allow,
                    ManagedEffectDecision::Allow,
                    ManagedEffectDecision::Allow,
                    ManagedEffectDecision::Allow
                ]
            )
    }

    /// Whether the policy has a supported version.
    pub const fn is_valid(self) -> bool {
        self.version == MANAGED_EFFECT_POLICY_VERSION
    }
}

/// Record and six-class rules observed under one T1 writer fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectTrustEffectPolicySnapshot {
    /// Unchanged durable T1 project record.
    pub record: ProjectTrustRecord,
    /// Exact managed effect policy associated with the record.
    pub policy: ManagedEffectPolicyV1,
}

impl ProjectTrustEffectPolicySnapshot {
    /// Whether the record and policy are structurally supported.
    pub const fn is_valid(self) -> bool {
        let record = self.record;
        self.policy.is_valid()
            && record.instance_epoch != 0
            && record.managed_deny_mask & !0x7f == 0
            && (record.revision != 0
                || (matches!(record.status, super::ProjectTrustStatus::Untrusted)
                    && record.managed_deny_mask == 0))
    }
}
