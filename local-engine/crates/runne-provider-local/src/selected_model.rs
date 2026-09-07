//! Selected-model authority (Plan Task 12, standalone transition
//! contract for the store's singleton record): explicit selection with
//! a monotonic generation, explicit `None` resolution (never an
//! inferred default), and the linearized local-installation removal
//! saga — verify not selected/loaded → `RemovalPending` + a one-time
//! fenced `ModelRemovalPermit` → completion consumes the permit and
//! releases the fence. Crash recovery rolls the saga forward or
//! safely restores availability before new selection.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub provider_id: String,
    pub model_id: String,
    pub manifest_digest: String,
    pub backend_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionGeneration(pub u64);

/// One-time removal permit (CAS token for the catalog authority).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRemovalPermit {
    pub manifest_digest: String,
    pub permit_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalStage {
    None,
    /// Fence held; catalog may consume the permit exactly once.
    Pending {
        permit: ModelRemovalPermit,
    },
    /// Completed; fence released, digest removed from eligibility.
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    /// The digest is fenced by a removal in flight or completed.
    RemovalFenced,
    /// Removal attempted while the model is still selected/loaded.
    InUse,
    /// A removal for another digest is already linearized.
    RemovalInFlight,
    /// Permit is missing, already consumed, or for another digest.
    PermitInvalid,
}

#[derive(Debug)]
pub struct SelectedModelStore {
    selected: Option<(Selection, SelectionGeneration)>,
    generation: u64,
    removal_digest: Option<String>,
    removal: RemovalStage,
    next_permit_id: u64,
    loaded: Option<String>,
}

impl Default for SelectedModelStore {
    fn default() -> Self {
        Self {
            selected: None,
            generation: 0,
            removal_digest: None,
            removal: RemovalStage::None,
            next_permit_id: 0,
            loaded: None,
        }
    }
}

impl SelectedModelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicit selection; bumps the monotonic generation. Refused
    /// while that digest is removal-fenced. `fence` is the caller's
    /// idempotency token: re-selecting with the same fence and fields
    /// is a no-op returning the existing generation.
    pub fn select(
        &mut self,
        selection: Selection,
        fence: Option<u64>,
    ) -> Result<SelectionGeneration, SelectionError> {
        if let Some(digest) = &self.removal_digest
            && *digest == selection.manifest_digest
        {
            return Err(SelectionError::RemovalFenced);
        }
        if let Some(f) = fence
            && f == self.generation
            && self.selected.as_ref().is_some_and(|(s, _)| *s == selection)
        {
            return Ok(self.current_generation());
        }
        self.generation += 1;
        let selection_generation = SelectionGeneration(self.generation);
        self.selected = Some((selection, selection_generation));
        Ok(selection_generation)
    }

    /// The durable selection or explicit `None` — never a default.
    pub fn resolve(&self) -> Option<(Selection, SelectionGeneration)> {
        self.selected.clone()
    }

    /// Current removal saga stage (diagnostics/recovery input).
    pub fn removal_stage(&self) -> &RemovalStage {
        &self.removal
    }

    /// Marks the loaded model identity for removal gating.
    pub fn set_loaded(&mut self, manifest_digest: Option<&str>) {
        self.loaded = manifest_digest.map(|s| s.to_string());
    }

    /// Begins the removal saga: verify not selected/loaded, fence the
    /// digest and issue the one-time permit.
    pub fn begin_removal(
        &mut self,
        manifest_digest: &str,
    ) -> Result<ModelRemovalPermit, SelectionError> {
        if matches!(self.removal, RemovalStage::Pending { .. }) {
            return Err(SelectionError::RemovalInFlight);
        }
        if self
            .selected
            .as_ref()
            .is_some_and(|(s, _)| s.manifest_digest == manifest_digest)
        {
            return Err(SelectionError::InUse);
        }
        if self.loaded.as_deref() == Some(manifest_digest) {
            return Err(SelectionError::InUse);
        }
        self.next_permit_id += 1;
        let permit = ModelRemovalPermit {
            manifest_digest: manifest_digest.to_string(),
            permit_id: self.next_permit_id,
        };
        self.removal_digest = Some(manifest_digest.to_string());
        self.removal = RemovalStage::Pending {
            permit: permit.clone(),
        };
        Ok(permit)
    }

    /// The catalog consumed the permit: record completion, release the
    /// fence. The permit is taken exactly once.
    pub fn complete_removal(&mut self, permit: ModelRemovalPermit) -> Result<(), SelectionError> {
        match &self.removal {
            RemovalStage::Pending { permit: held } if *held == permit => {
                self.removal = RemovalStage::Completed;
                self.removal_digest = None;
                Ok(())
            }
            _ => Err(SelectionError::PermitInvalid),
        }
    }

    /// Crash recovery: a pending saga rolls forward to completed only
    /// with the exact permit; otherwise availability is restored (the
    /// fence releases and the digest is selectable again).
    pub fn recover(&mut self, held_permit: Option<ModelRemovalPermit>) -> bool {
        match (&self.removal, held_permit) {
            (RemovalStage::Pending { permit }, Some(held)) if *permit == held => {
                self.removal = RemovalStage::Completed;
                self.removal_digest = None;
                true
            }
            (RemovalStage::Pending { .. }, None) => {
                // No permit survived the crash: restore availability.
                self.removal = RemovalStage::None;
                self.removal_digest = None;
                false
            }
            _ => false,
        }
    }

    fn current_generation(&self) -> SelectionGeneration {
        SelectionGeneration(self.generation)
    }
}
