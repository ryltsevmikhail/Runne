/// Bounded bootstrap frame supplied by a plugin transport implementation.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginBootstrapFrame(Box<[u8]>);

impl PluginBootstrapFrame {
    /// Retains an outbound frame constructed by the host.
    pub(crate) fn outbound(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Returns the immutable bytes for a certified external transport backend.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Exact activation binding that a process backend must certify.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginProcessLease {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Opaque backend evidence that the exact process accepted a drain boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginDrainEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Opaque backend evidence that cleanup closed containment for the exact
/// terminal process.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginCleanupEvidence {
    activation_id: PluginActivationId,
    package_digest: PluginDigest,
    generation: PluginGeneration,
    reservation: [u8; 32],
}

/// Registry-owned generation read lease held across activation negotiation.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginGenerationReadLease {
    activation_id: PluginActivationId,
    generation: PluginGeneration,
}

/// Registry-issued binding proving an activation became ready under one exact
/// generation and negotiation snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginActiveFence {
    activation_id: PluginActivationId,
    generation: PluginGeneration,
    negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
}

impl PluginActiveFence {
    pub(crate) fn issued(
        lease: &PluginGenerationReadLease,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            generation: lease.generation,
            negotiation_snapshot,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        generation: PluginGeneration,
        negotiation_snapshot: ProtocolNegotiationSnapshotDigest,
    ) -> bool {
        self.activation_id == *activation_id
            && self.generation == generation
            && self.negotiation_snapshot == negotiation_snapshot
    }

    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }

    pub(crate) const fn negotiation_snapshot(&self) -> ProtocolNegotiationSnapshotDigest {
        self.negotiation_snapshot
    }
}

impl PluginGenerationReadLease {
    pub(crate) fn issued(activation_id: PluginActivationId, generation: PluginGeneration) -> Self {
        Self {
            activation_id,
            generation,
        }
    }

    pub(crate) fn matches(
        &self,
        activation_id: &PluginActivationId,
        generation: PluginGeneration,
    ) -> bool {
        self.activation_id == *activation_id && self.generation == generation
    }

    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }
}

impl PluginProcessLease {
    /// Creates evidence emitted only by a certified process backend.
    #[cfg(test)]
    pub(crate) fn certified(intent: &PluginStartIntent) -> Self {
        Self {
            activation_id: intent.activation_id.clone(),
            package_digest: intent.package_digest,
            generation: intent.generation,
            reservation: *intent.reservation(),
        }
    }

    pub(crate) fn matches(&self, intent: &PluginStartIntent) -> bool {
        self.activation_id == intent.activation_id
            && self.package_digest == intent.package_digest
            && self.generation == intent.generation
            && self.reservation == *intent.reservation()
    }

    #[cfg(test)]
    pub(crate) fn activation_id(&self) -> &PluginActivationId {
        &self.activation_id
    }

    #[cfg(test)]
    pub(crate) const fn package_digest(&self) -> PluginDigest {
        self.package_digest
    }

    #[cfg(test)]
    pub(crate) const fn generation(&self) -> PluginGeneration {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn reservation(&self) -> &[u8; 32] {
        &self.reservation
    }
}

impl PluginDrainEvidence {
    #[cfg(test)]
    pub(crate) fn certified(lease: &PluginProcessLease) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            package_digest: lease.package_digest,
            generation: lease.generation,
            reservation: lease.reservation,
        }
    }

    pub(crate) fn matches(&self, lease: &PluginProcessLease) -> bool {
        self.activation_id == lease.activation_id
            && self.package_digest == lease.package_digest
            && self.generation == lease.generation
            && self.reservation == lease.reservation
    }
}

impl PluginCleanupEvidence {
    #[cfg(test)]
    pub(crate) fn certified(lease: &PluginProcessLease) -> Self {
        Self {
            activation_id: lease.activation_id.clone(),
            package_digest: lease.package_digest,
            generation: lease.generation,
            reservation: lease.reservation,
        }
    }

    pub(crate) fn matches(&self, lease: &PluginProcessLease) -> bool {
        self.activation_id == lease.activation_id
            && self.package_digest == lease.package_digest
            && self.generation == lease.generation
            && self.reservation == lease.reservation
    }
}
