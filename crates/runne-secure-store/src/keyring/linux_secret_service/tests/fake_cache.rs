//! Deterministic fake keyutils cache half.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::keyring::linux_secret_service::cache::{
    CacheDeletionOutcome, CacheError, KeyutilsCache,
};

pub struct FakeKeyutilsCache {
    entries: HashMap<String, Vec<u8>>,
    pub fail_set: bool,
    pub fail_get: bool,
    pub fail_delete: bool,
    pub fail_restore: bool,
    pub fail_delete_after_set: bool,
    /// Fails only the Nth delete call (1-based) for targeted fault injection.
    pub fail_delete_call: Option<usize>,
    delete_calls: usize,
    fresh_insertion: bool,
    set_counts: HashMap<String, usize>,
    /// Simulates the kernel in-process cache lag: a deleted key is still
    /// found by the immediately following search.
    pub stale_after_delete: bool,
}

impl FakeKeyutilsCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            fail_set: false,
            fail_get: false,
            fail_delete: false,
            fail_restore: false,
            fail_delete_after_set: false,
            fail_delete_call: None,
            delete_calls: 0,
            fresh_insertion: false,
            set_counts: HashMap::new(),
            stale_after_delete: false,
        }
    }

    pub fn seed(&mut self, description: &str, secret: &[u8]) {
        self.entries.insert(description.to_owned(), secret.to_vec());
    }

    pub fn contains(&self, description: &str) -> bool {
        self.entries.contains_key(description)
    }
}

impl Default for FakeKeyutilsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyutilsCache for FakeKeyutilsCache {
    fn set(&mut self, description: &str, secret: &[u8]) -> Result<(), CacheError> {
        let prior_sets = self.set_counts.get(description).copied().unwrap_or(0);
        if self.fail_set || self.fail_restore && prior_sets >= 1 {
            return Err(CacheError::Unavailable);
        }
        self.set_counts
            .insert(description.to_owned(), prior_sets + 1);
        self.fresh_insertion = !self.entries.contains_key(description);
        self.entries.insert(description.to_owned(), secret.to_vec());
        Ok(())
    }

    fn get(&mut self, description: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {
        if self.fail_get {
            return Err(CacheError::Unavailable);
        }
        Ok(self
            .entries
            .get(description)
            .map(|value| Zeroizing::new(value.clone())))
    }

    fn delete(&mut self, description: &str) -> Result<CacheDeletionOutcome, CacheError> {
        self.delete_calls += 1;
        if self.fail_delete
            || self.fail_delete_after_set && self.fresh_insertion
            || self.fail_delete_call == Some(self.delete_calls)
        {
            return Err(CacheError::Unavailable);
        }
        self.fresh_insertion = false;
        if self.entries.remove(description).is_some() {
            if self.stale_after_delete {
                self.entries
                    .insert(description.to_owned(), b"stale-kernel-cache".to_vec());
            }
            return Ok(CacheDeletionOutcome::Deleted);
        }
        Ok(CacheDeletionOutcome::Absent)
    }
}
