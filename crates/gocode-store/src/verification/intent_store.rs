use gocode_domain::verification::digest::VerificationDigest;
use gocode_domain::verification::evaluation::{IntentError, IntentStore};
use gocode_domain::verification::identity::*;
use gocode_domain::verification::intent::{ConsumptionIntent, DispatchEvidence};
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory intent store with CAS semantics and fencing.
pub struct InMemoryIntentStore {
    store: Mutex<IntentStore>,
}

impl InMemoryIntentStore {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(IntentStore::new()),
        }
    }

    pub fn reserve(
        &self,
        intent_id: IntentID,
        key: &str,
        snapshot: VerificationDigest,
        target: VerificationDigest,
    ) -> Result<ConsumptionIntent, IntentError> {
        self.store
            .lock()
            .unwrap()
            .reserve(intent_id, key, snapshot, target)
    }

    pub fn claim_dispatching(
        &self,
        intent_id: &IntentID,
        expected_digest: &VerificationDigest,
    ) -> Result<(), IntentError> {
        self.store
            .lock()
            .unwrap()
            .claim_dispatching(intent_id, expected_digest)?;
        Ok(())
    }

    pub fn invalidate(&self, intent_id: &IntentID) -> Result<(), IntentError> {
        self.store.lock().unwrap().invalidate(intent_id)
    }

    pub fn settle(&self, intent_id: &IntentID, success: bool) -> Result<(), IntentError> {
        self.store.lock().unwrap().settle(intent_id, success)
    }

    pub fn reconcile(
        &self,
        intent_id: &IntentID,
        evidence: &DispatchEvidence,
    ) -> Result<(), IntentError> {
        self.store.lock().unwrap().reconcile(intent_id, evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn td(b: u8) -> VerificationDigest {
        VerificationDigest::from_bytes([b; 32])
    }

    #[test]
    fn intent_full_lifecycle() {
        let store = InMemoryIntentStore::new();
        let id = Uuid::now_v7();
        store.reserve(id, "key1", td(1), td(2)).unwrap();
        store.claim_dispatching(&id, &td(0)).unwrap();
        store.settle(&id, true).unwrap();
    }

    #[test]
    fn intent_invalidated_claim_rejected() {
        let store = InMemoryIntentStore::new();
        let id = Uuid::now_v7();
        store.reserve(id, "key1", td(1), td(2)).unwrap();
        store.invalidate(&id).unwrap();
        assert!(store.claim_dispatching(&id, &td(0)).is_err());
    }

    #[test]
    fn intent_dispatching_not_invalidated() {
        let store = InMemoryIntentStore::new();
        let id = Uuid::now_v7();
        store.reserve(id, "key1", td(1), td(2)).unwrap();
        store.claim_dispatching(&id, &td(0)).unwrap();
        // Invalidate is no-op when dispatching
        store.invalidate(&id).unwrap();
        store.settle(&id, true).unwrap();
    }
}
