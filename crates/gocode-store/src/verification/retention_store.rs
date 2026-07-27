use gocode_domain::verification::backup::{PruningEntry, RetentionPolicy};
use gocode_domain::verification::identity::RunID;
use std::collections::HashSet;
use std::sync::Mutex;

pub struct InMemoryRetentionStore {
    journal: Mutex<Vec<PruningEntry>>,
    active_refs: Mutex<HashSet<RunID>>,
}

impl InMemoryRetentionStore {
    pub fn new() -> Self {
        Self {
            journal: Mutex::new(vec![]),
            active_refs: Mutex::new(HashSet::new()),
        }
    }

    pub fn find_detachable(
        &self,
        runs: &[(RunID, u32, bool)],
        policy: &RetentionPolicy,
    ) -> Vec<RunID> {
        let active = self.active_refs.lock().unwrap();
        let keep_last = policy.keep_last_n_runs_per_plan as usize;
        runs.iter()
            .filter(|(_, age_days, is_failed)| {
                if *is_failed && *age_days < policy.keep_failed_runs_days {
                    return false;
                }
                *age_days >= policy.retention_days
            })
            .skip(keep_last)
            .map(|(id, _, _)| *id)
            .filter(|id| !active.contains(id))
            .take(policy.prune_batch_size as usize)
            .collect()
    }

    pub fn detach(&self, run_ids: &[RunID], reason: &str) -> Vec<PruningEntry> {
        let mut journal = self.journal.lock().unwrap();
        let entries: Vec<_> = run_ids
            .iter()
            .map(|id| PruningEntry {
                run_id: *id,
                reason: reason.to_string(),
                pruned_at: "now".into(),
                blob_count: 1,
            })
            .collect();
        journal.extend(entries.clone());
        entries
    }

    pub fn journal_entries(&self) -> usize {
        self.journal.lock().unwrap().len()
    }

    pub fn mark_active(&self, id: RunID) {
        self.active_refs.lock().unwrap().insert(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn retention_keeps_last_n() {
        let s = InMemoryRetentionStore::new();
        let runs: Vec<_> = (0..10).map(|_| (Uuid::now_v7(), 100u32, false)).collect();
        let policy = RetentionPolicy::new(30, 3, 90, 10).unwrap();
        let d = s.find_detachable(&runs, &policy);
        assert_eq!(d.len(), 7);
    }
    #[test]
    fn retention_keeps_failed_longer() {
        let s = InMemoryRetentionStore::new();
        let runs = vec![(Uuid::now_v7(), 50u32, true)];
        let policy = RetentionPolicy::new(30, 1, 90, 10).unwrap();
        assert!(s.find_detachable(&runs, &policy).is_empty());
    }
    #[test]
    fn retention_respects_batch() {
        let s = InMemoryRetentionStore::new();
        let runs: Vec<_> = (0..100).map(|_| (Uuid::now_v7(), 100u32, false)).collect();
        let policy = RetentionPolicy::new(30, 0, 90, 5).unwrap();
        assert_eq!(s.find_detachable(&runs, &policy).len(), 5);
    }
    #[test]
    fn retention_protects_active_refs() {
        let s = InMemoryRetentionStore::new();
        let id = Uuid::now_v7();
        s.mark_active(id);
        let runs = vec![(id, 100u32, false)];
        let policy = RetentionPolicy::new(30, 0, 90, 10).unwrap();
        assert!(s.find_detachable(&runs, &policy).is_empty());
    }
    #[test]
    fn retention_journal_records() {
        let s = InMemoryRetentionStore::new();
        let ids: Vec<_> = (0..3).map(|_| Uuid::now_v7()).collect();
        let entries = s.detach(&ids, "test");
        assert_eq!(entries.len(), 3);
        assert_eq!(s.journal_entries(), 3);
    }
}
