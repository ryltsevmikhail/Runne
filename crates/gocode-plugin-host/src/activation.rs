//! Fail-closed plugin activation and exact bootstrap profile negotiation.
#![allow(missing_docs)]

use gocode_plugin_protocol::bootstrap::{
    BootstrapMessage, HostHello, PluginHello, ProfileSelected,
};
use gocode_plugin_protocol::bootstrap_v2::SelectionAcknowledgedV2;
use gocode_plugin_protocol::digest::{
    DigestAlgorithm, PackageDigest, ProtocolNegotiationSnapshotDigest,
};
use gocode_plugin_protocol::frame::{FrameLimits, decode_codec_frame, decode_frame, encode_frame};
use gocode_plugin_protocol::id::PluginId;
use gocode_plugin_protocol::id::{Nonce, ProtocolSessionId};
use gocode_plugin_protocol::profile::DecodeLimits;

use crate::{
    PluginActivationId, PluginActiveFence, PluginBootstrapFrame, PluginCleanupEvidence,
    PluginDigest, PluginDrainEvidence, PluginGeneration, PluginGenerationPort,
    PluginGenerationReadLease, PluginProcessLease, PluginProcessPort, PluginProcessPortError,
    PluginStartIntent, PluginStartIntentOrigin, PluginStartIntentPort, PluginStartReconciliation,
    PluginTransportPort, VerifiedPluginPackage,
};

const MAX_BOOTSTRAP_FRAME_BYTES: usize = 64 * 1024;
const MAX_ACTIVATION_RECEIPTS: usize = 16;

/// Ordered lifecycle states for one plugin activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationState {
    Verified,
    Starting,
    Negotiating,
    Active,
    Draining,
    Terminal,
    Uncertain,
}

include!("activation/state_types.rs");
include!("activation/state_setup.rs");
include!("activation/state_reconcile.rs");
include!("activation/state_lifecycle.rs");
include!("activation/terminal.rs");
include!("activation/request_type.rs");
include!("activation/request_api.rs");
include!("activation/request_activation.rs");
include!("activation/request_accessors.rs");
include!("activation/request_handshake.rs");

#[cfg(test)]
mod tests;
