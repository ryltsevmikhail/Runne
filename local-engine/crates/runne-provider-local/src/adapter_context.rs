//! Construction and read-only adapter context operations.

use crate::adapter::{LocalExecutionPermitPort, LocalProviderAdapter, LocalUsageSettlementPort};
use std::collections::BTreeMap;
use std::path::PathBuf;

impl<
    PermitPortT: LocalExecutionPermitPort + Send + Sync,
    SettlePortT: LocalUsageSettlementPort + Send + Sync,
> LocalProviderAdapter<PermitPortT, SettlePortT>
{
    pub fn new(
        permit_port: PermitPortT,
        settlement: SettlePortT,
        known_manifests: BTreeMap<String, String>,
        blobs_dir: PathBuf,
    ) -> Self {
        Self {
            permit_port,
            settlement,
            known_manifests,
            streams: BTreeMap::new(),
            settled: std::collections::BTreeSet::new(),
            terminal_evidence: std::collections::BTreeSet::new(),
            dispatched_no_evidence: std::collections::BTreeSet::new(),
            cancelling: std::collections::BTreeSet::new(),
            blobs_dir,
        }
    }

    /// True once a cancel intent was recorded for the stream.
    pub fn cancelling(&self, stream_id: &[u8; 16]) -> bool {
        self.cancelling.contains(stream_id)
    }
}
