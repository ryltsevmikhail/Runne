use super::{
    FixtureApproval, FixtureApprovalAuthority, FixtureAuditRecord, FixtureCallCapability,
    FixtureIdentity, FixtureInitialize, FixtureMcpRuntime, FixturePublication, FixtureScript,
    FixtureStep, FixtureTool,
};

macro_rules! metadata_debug {
    ($type:ty, $name:literal) => {
        impl core::fmt::Debug for $type {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter
                    .debug_struct($name)
                    .field("fixture_only", &true)
                    .finish()
            }
        }
    };
}

metadata_debug!(FixtureIdentity, "FixtureIdentity");
metadata_debug!(FixtureInitialize, "FixtureInitialize");
metadata_debug!(FixtureTool, "FixtureTool");
metadata_debug!(FixtureScript, "FixtureScript");
metadata_debug!(FixtureStep, "FixtureStep");
metadata_debug!(FixtureApproval, "FixtureApproval");
metadata_debug!(FixtureApprovalAuthority, "FixtureApprovalAuthority");

impl core::fmt::Debug for FixtureAuditRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FixtureAuditRecord")
            .field("fixture_only", &true)
            .finish()
    }
}

impl core::fmt::Debug for FixtureCallCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FixtureCallCapability")
            .field("has_capability", &self.capability.is_some())
            .field("execution_class", &self.execution_class)
            .field("has_process_payload", &self.process_payload.is_some())
            .field("generation", &self.generation)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl core::fmt::Debug for FixturePublication {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FixturePublication")
            .field("tool_count", &self.tools.len())
            .field("generation", &self.binding.generation())
            .finish()
    }
}

impl core::fmt::Debug for FixtureMcpRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("FixtureMcpRuntime").finish()
    }
}
