//! Bounded dispatch queue (Plan Task 12 Step 4): finite, runtime-
//! scheduler owned order. A full queue refuses; an attempt for a
//! different selected model never evicts or falls back implicitly;
//! the single loaded-model slot conflicts instead of switching.

use crate::error::ProviderError;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Full,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    pub attempt_id: [u8; 16],
    /// Identity the attempt is bound to; mismatch with the loaded
    /// model conflicts at the front, it never re-points the queue.
    pub model_identity: String,
}

#[derive(Debug)]
pub struct BoundedDispatchQueue {
    capacity: usize,
    items: VecDeque<QueueItem>,
    loaded_model: Option<String>,
    closed: bool,
}

impl BoundedDispatchQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            items: VecDeque::new(),
            loaded_model: None,
            closed: false,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Points the queue at the currently loaded model (the selection).
    pub fn set_loaded_model(&mut self, model_identity: &str) {
        self.loaded_model = Some(model_identity.to_string());
    }

    /// Closes the queue to new arrivals (idle-drain path).
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Enqueues under the finite capacity; a closed queue refuses.
    pub fn push(&mut self, item: QueueItem) -> Result<(), ProviderError> {
        if self.closed {
            return Err(ProviderError::QueueClosed);
        }
        if self.items.len() >= self.capacity {
            return Err(ProviderError::QueueFull);
        }
        self.items.push_back(item);
        Ok(())
    }

    /// Pops the next item; an item for a DIFFERENT loaded model is
    /// returned as a conflict (the scheduler decides), never silently
    /// dropped or swapped.
    pub fn pop(&mut self) -> Result<Option<QueueItem>, ProviderError> {
        let Some(item) = self.items.pop_front() else {
            return Ok(None);
        };
        if let Some(loaded) = &self.loaded_model
            && &item.model_identity != loaded
        {
            // Put it back at the front: no implicit eviction.
            self.items.push_front(item);
            return Err(ProviderError::OneLoadedModelConflict);
        }
        Ok(Some(item))
    }

    /// Idle unload precondition: no active attempts at all.
    pub fn drain_idle(&mut self) -> bool {
        self.items.is_empty()
    }
}
