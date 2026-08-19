//! Bounded HTTP and replay transport resource ownership.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

pub const MAX_REPLAY_BODY_BYTES: usize = 8 * 1024;
pub const DEFAULT_REPLAY_PAGE_SIZE: usize = 100;
pub const MAX_REPLAY_PAGE_SIZE: usize = 256;
pub const MAX_ENCODED_REPLAY_PAGE_BYTES: usize = 1024 * 1024;
pub const MAX_LIVE_QUEUE_FRAMES: usize = 64;
pub const MAX_LIVE_QUEUE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_GLOBAL_REPLAY_QUEUE_BYTES: usize = 32 * 1024 * 1024;

const MAX_REPLAY_SESSIONS_PER_PRINCIPAL: usize = 8;
const MAX_REPLAY_SESSIONS_PER_DAEMON: usize = 32;
const MAX_LIVE_STREAMS_PER_PRINCIPAL: usize = 4;
const MAX_LIVE_STREAMS_PER_DAEMON: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_max_page_size")]
    pub max_page_size: usize,
    #[serde(default = "default_page_size")]
    pub default_page_size: usize,
}

const fn default_max_body_size() -> usize {
    MAX_REPLAY_BODY_BYTES
}

const fn default_max_page_size() -> usize {
    MAX_REPLAY_PAGE_SIZE
}

const fn default_page_size() -> usize {
    DEFAULT_REPLAY_PAGE_SIZE
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            max_page_size: default_max_page_size(),
            default_page_size: default_page_size(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayQuotaError {
    Backpressure,
}

#[derive(Default)]
struct ReplayQuotaState {
    sessions_by_principal: HashMap<String, usize>,
    session_count: usize,
    live_by_principal: HashMap<String, usize>,
    live_count: usize,
    queued_bytes: usize,
}

#[derive(Clone, Default)]
pub struct ReplayQuotaManager {
    state: Arc<Mutex<ReplayQuotaState>>,
}

impl ReplayQuotaManager {
    pub fn reserve_session(&self, principal: &str) -> Result<ReplayCountPermit, ReplayQuotaError> {
        self.reserve_count(
            principal,
            CountKind::Session,
            MAX_REPLAY_SESSIONS_PER_PRINCIPAL,
            MAX_REPLAY_SESSIONS_PER_DAEMON,
        )
    }

    pub fn reserve_live(&self, principal: &str) -> Result<ReplayCountPermit, ReplayQuotaError> {
        self.reserve_count(
            principal,
            CountKind::Live,
            MAX_LIVE_STREAMS_PER_PRINCIPAL,
            MAX_LIVE_STREAMS_PER_DAEMON,
        )
    }

    pub fn queue(&self) -> ReplayQueueQuota {
        ReplayQueueQuota {
            manager: self.clone(),
            queued_bytes: Arc::new(Mutex::new(0)),
        }
    }

    fn reserve_count(
        &self,
        principal: &str,
        kind: CountKind,
        principal_limit: usize,
        daemon_limit: usize,
    ) -> Result<ReplayCountPermit, ReplayQuotaError> {
        if principal.is_empty() {
            return Err(ReplayQuotaError::Backpressure);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayQuotaError::Backpressure)?;
        let principal_count = match kind {
            CountKind::Session => state
                .sessions_by_principal
                .get(principal)
                .copied()
                .unwrap_or(0),
            CountKind::Live => state.live_by_principal.get(principal).copied().unwrap_or(0),
        };
        let total = match kind {
            CountKind::Session => state.session_count,
            CountKind::Live => state.live_count,
        };
        if principal_count >= principal_limit || total >= daemon_limit {
            return Err(ReplayQuotaError::Backpressure);
        }
        match kind {
            CountKind::Session => {
                state
                    .sessions_by_principal
                    .insert(principal.to_owned(), principal_count + 1);
                state.session_count += 1;
            }
            CountKind::Live => {
                state
                    .live_by_principal
                    .insert(principal.to_owned(), principal_count + 1);
                state.live_count += 1;
            }
        }
        Ok(ReplayCountPermit {
            manager: self.clone(),
            principal: principal.to_owned(),
            kind,
        })
    }
}

#[derive(Clone, Copy)]
enum CountKind {
    Session,
    Live,
}

pub struct ReplayCountPermit {
    manager: ReplayQuotaManager,
    principal: String,
    kind: CountKind,
}

impl fmt::Debug for ReplayCountPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayCountPermit")
            .finish_non_exhaustive()
    }
}

impl Drop for ReplayCountPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.manager.state.lock() {
            match self.kind {
                CountKind::Session => {
                    decrement_principal(&mut state.sessions_by_principal, &self.principal);
                    state.session_count = state.session_count.saturating_sub(1);
                }
                CountKind::Live => {
                    decrement_principal(&mut state.live_by_principal, &self.principal);
                    state.live_count = state.live_count.saturating_sub(1);
                }
            }
        }
    }
}

fn decrement_principal(counts: &mut HashMap<String, usize>, principal: &str) {
    if let Some(count) = counts.get_mut(principal) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(principal);
        }
    }
}

#[derive(Clone)]
pub struct ReplayQueueQuota {
    manager: ReplayQuotaManager,
    queued_bytes: Arc<Mutex<usize>>,
}

impl ReplayQueueQuota {
    pub fn reserve(&self, bytes: usize) -> Result<ReplayQueuePermit, ReplayQuotaError> {
        if bytes == 0 || bytes > MAX_LIVE_QUEUE_BYTES {
            return Err(ReplayQuotaError::Backpressure);
        }
        let mut global = self
            .manager
            .state
            .lock()
            .map_err(|_| ReplayQuotaError::Backpressure)?;
        let mut queue = self
            .queued_bytes
            .lock()
            .map_err(|_| ReplayQuotaError::Backpressure)?;
        let next_queue = queue
            .checked_add(bytes)
            .ok_or(ReplayQuotaError::Backpressure)?;
        let next_global = global
            .queued_bytes
            .checked_add(bytes)
            .ok_or(ReplayQuotaError::Backpressure)?;
        if next_queue > MAX_LIVE_QUEUE_BYTES || next_global > MAX_GLOBAL_REPLAY_QUEUE_BYTES {
            return Err(ReplayQuotaError::Backpressure);
        }
        *queue = next_queue;
        global.queued_bytes = next_global;
        Ok(ReplayQueuePermit {
            quota: self.clone(),
            bytes,
        })
    }
}

pub struct ReplayQueuePermit {
    quota: ReplayQueueQuota,
    bytes: usize,
}

impl fmt::Debug for ReplayQueuePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayQueuePermit")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for ReplayQueuePermit {
    fn drop(&mut self) {
        if let Ok(mut global) = self.quota.manager.state.lock()
            && let Ok(mut queue) = self.quota.queued_bytes.lock()
        {
            *queue = queue.saturating_sub(self.bytes);
            global.queued_bytes = global.queued_bytes.saturating_sub(self.bytes);
        }
    }
}
