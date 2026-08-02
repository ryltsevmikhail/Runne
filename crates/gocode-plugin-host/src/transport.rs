//! Project-owned process and bootstrap transport ports for plugin activation.

use crate::{PluginActivationId, PluginDigest, PluginGeneration};
use gocode_plugin_protocol::digest::ProtocolNegotiationSnapshotDigest;

include!("transport/intent.rs");
include!("transport/process.rs");
include!("transport/ports.rs");

#[cfg(test)]
mod tests {
    include!("transport/tests.rs");
}
