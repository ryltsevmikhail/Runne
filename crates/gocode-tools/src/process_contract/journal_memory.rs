use std::collections::BTreeMap;

use super::{
    ProcessClaimJournalPort, ProcessClaimKeyV1, ProcessClaimRecordV1, ProcessContractErrorV1,
};

/// Deterministic metadata-only in-memory projection store for sealed process claims.
#[derive(Default)]
pub struct ProcessClaimJournalMemoryV1 {
    records: BTreeMap<String, ProcessClaimRecordV1>,
}

/// Opaque metadata-only recovery snapshot for an in-memory claim journal.
#[derive(Clone)]
pub struct ProcessClaimJournalMemorySnapshotV1 {
    records: BTreeMap<String, ProcessClaimRecordV1>,
}

impl ProcessClaimJournalMemoryV1 {
    /// Creates an empty journal without any effect or platform authority.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies the exact claim projection for an explicit recovery boundary.
    #[must_use]
    pub fn snapshot(&self) -> ProcessClaimJournalMemorySnapshotV1 {
        ProcessClaimJournalMemorySnapshotV1 {
            records: self.records.clone(),
        }
    }

    /// Reopens an exact journal snapshot without dispatching an effect.
    #[must_use]
    pub fn reopen(snapshot: ProcessClaimJournalMemorySnapshotV1) -> Self {
        Self {
            records: snapshot.records,
        }
    }
}

impl ProcessClaimJournalPort for ProcessClaimJournalMemoryV1 {
    fn read(
        &self,
        key: &ProcessClaimKeyV1,
    ) -> Result<Option<ProcessClaimRecordV1>, ProcessContractErrorV1> {
        Ok(self.records.get(key.permit_id()).cloned())
    }

    fn compare_and_set(
        &mut self,
        key: &ProcessClaimKeyV1,
        expected: Option<&ProcessClaimRecordV1>,
        replacement: ProcessClaimRecordV1,
    ) -> Result<bool, ProcessContractErrorV1> {
        if self.records.get(key.permit_id()) != expected {
            return Ok(false);
        }
        self.records.insert(key.permit_id().to_owned(), replacement);
        Ok(true)
    }
}
