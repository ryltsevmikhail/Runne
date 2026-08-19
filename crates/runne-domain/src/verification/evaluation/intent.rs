// ===== ConsumptionIntent Store =====

/// ConsumptionIntent CAS store with fencing support.
#[derive(Clone, Debug, Default)]
pub struct IntentStore {
    intents: HashMap<IntentID, ConsumptionIntent>,
}

impl IntentStore {
    pub fn new() -> Self {
        Self {
            intents: HashMap::new(),
        }
    }

    /// Reserve intent atomically. Duplicate → prior outcome.
    pub fn reserve(
        &mut self,
        intent_id: IntentID,
        idempotency_key: &str,
        snapshot_digest: VerificationDigest,
        target_digest: VerificationDigest,
    ) -> Result<ConsumptionIntent, IntentError> {
        if let Some(existing) = self.intents.get(&intent_id) {
            if existing.idempotency_key == idempotency_key {
                return Ok(existing.clone());
            }
            return Err(IntentError::AlreadyReserved);
        }
        let intent = ConsumptionIntent {
            intent_id,
            idempotency_key: idempotency_key.to_string(),
            state: IntentState::Reserved,
            gate_head_snapshot_digest: snapshot_digest,
            target_artifact_digest: target_digest,
            integrity_digest: VerificationDigest::from_bytes([0; 32]),
        };
        self.intents.insert(intent_id, intent);
        Ok(self.intents.get(&intent_id).unwrap().clone())
    }

    /// Atomically claim dispatching.
    pub fn claim_dispatching(
        &mut self,
        intent_id: &IntentID,
        expected_digest: &VerificationDigest,
    ) -> Result<&ConsumptionIntent, IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state == IntentState::Invalidated {
            return Err(IntentError::IntentInvalidated);
        }
        if intent.state != IntentState::Reserved {
            return Err(IntentError::InvalidTransition);
        }
        if &intent.integrity_digest != expected_digest
            && !expected_digest.as_bytes().iter().all(|b| *b == 0)
        {
            return Err(IntentError::DigestMismatch);
        }
        intent.state = IntentState::Dispatching;
        Ok(intent)
    }

    /// Invalidate intent (called by Gate CAS when gate changes under reserved intent).
    pub fn invalidate(&mut self, intent_id: &IntentID) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state != IntentState::Reserved {
            return Ok(());
        } // dispatching → not invalidated
        intent.state = IntentState::Invalidated;
        Ok(())
    }

    /// Settle after effect.
    pub fn settle(&mut self, intent_id: &IntentID, success: bool) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        if intent.state != IntentState::Dispatching {
            return Err(IntentError::InvalidTransition);
        }
        intent.state = if success {
            IntentState::Completed
        } else {
            IntentState::Failed
        };
        Ok(())
    }

    /// Reconcile from dispatch evidence.
    pub fn reconcile(
        &mut self,
        intent_id: &IntentID,
        evidence: &DispatchEvidence,
    ) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or(IntentError::IntentNotFound)?;
        match evidence {
            DispatchEvidence::NotStarted => {
                if intent.state == IntentState::Dispatching {
                    intent.state = IntentState::Abandoned;
                }
            }
            DispatchEvidence::Acknowledged { outcome, .. } => {
                if intent.state == IntentState::Dispatching {
                    intent.state = if outcome == "success" {
                        IntentState::Completed
                    } else {
                        IntentState::Failed
                    };
                }
            }
            DispatchEvidence::Unknown => {} // stay dispatching, unresolved
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IntentError {
    AlreadyReserved,
    IdempotencyConflict,
    IntentNotFound,
    IntentInvalidated,
    InvalidTransition,
    DigestMismatch,
    CorruptStore,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyReserved => write!(f, "intent already reserved"),
            Self::IdempotencyConflict => {
                write!(f, "idempotency reservation conflicts with stored intent")
            }
            Self::IntentNotFound => write!(f, "intent not found"),
            Self::IntentInvalidated => write!(f, "intent invalidated"),
            Self::InvalidTransition => write!(f, "invalid state transition"),
            Self::DigestMismatch => write!(f, "digest mismatch"),
            Self::CorruptStore => write!(f, "intent store contains malformed data"),
        }
    }
}
impl std::error::Error for IntentError {}
