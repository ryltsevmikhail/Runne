//! Unique-name-bound Secret Service facade (Linux persistent half).
//!
//! DESIGN v6 §4-P4/§6-F5: resolve the current owner of the well-known Secret
//! Service name, validate it, then address EVERY operation — including
//! `OpenSession` — to the resolved unique name on one connection. The owner is
//! re-checked before every operation; owner loss or change fails closed with
//! no retry and no new-owner fallback. Locked items are fail-closed: the
//! facade has no prompt and no unlock surface at all, so no dispatch or
//! enrollment path can trigger a dialog through it (§4-P3, F1′). An owner who
//! must unlock the collection does so through OS-native means outside Runne
//! and retries; the facade then reports `Locked` until then (§7).
//!
//! Classification: Target (this slice).

use zeroize::Zeroizing;

use super::dh_session::DhSession;
use super::item_layout::{self, EntryIdentity};
use super::owner::{OwnerBinding, OwnerError, ProcessFacts};
use super::port::{SecretServiceBus, SsBusError, SsMutationOutcome, SsSearchOutcome};

pub const SECRETS_WELL_KNOWN: &str = "org.freedesktop.secrets";
const DEFAULT_COLLECTION_ALIAS: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsFacadeError {
    /// Transport failed (service unreachable, peer died mid-call).
    Unavailable,
    /// Well-known name currently has no owner; never activated by us.
    OwnerMissing,
    /// Resolved owner failed validation (uid/exe/ownership).
    OwnerInvalid,
    /// Owner changed or was lost after binding; fail closed, no retry.
    OwnerLost,
    /// A matching item (or the target collection) is locked.
    Locked,
    /// Attribute search matched more than one item.
    Ambiguous,
    /// The service demanded an interactive prompt we never execute.
    Rejected,
}

impl SsFacadeError {
    pub const fn description(self) -> &'static str {
        match self {
            Self::Unavailable => "secret service unavailable",
            Self::OwnerMissing => "secret service owner missing",
            Self::OwnerInvalid => "secret service owner invalid",
            Self::OwnerLost => "secret service owner lost",
            Self::Locked => "secret service item locked",
            Self::Ambiguous => "secret service item ambiguous",
            Self::Rejected => "secret service prompt required",
        }
    }
}

/// One owner-bound encrypted Secret Service session.
pub struct BoundSecretService<B: SecretServiceBus, F: ProcessFacts> {
    bus: B,
    facts: F,
    owner: OwnerBinding,
    session: DhSession,
}

impl<B: SecretServiceBus, F: ProcessFacts> BoundSecretService<B, F> {
    /// Resolves, validates, and binds the current owner; opens the encrypted
    /// DH session directly with the resolved unique name.
    pub fn bind(mut bus: B, facts: F) -> Result<Self, SsFacadeError> {
        let unique_name = bus
            .name_owner(SECRETS_WELL_KNOWN)
            .map_err(unavailable)?
            .ok_or(SsFacadeError::OwnerMissing)?;
        let peer = bus.peer_credentials(&unique_name).map_err(unavailable)?;
        let owner = OwnerBinding::validate(&facts, unique_name, peer).map_err(map_owner_error)?;
        let dest = owner.unique_name.clone();
        let session =
            DhSession::negotiate(|algorithm, public| bus.open_session(&dest, algorithm, public))
                .map_err(unavailable)?;
        Ok(Self {
            bus,
            facts,
            owner,
            session,
        })
    }

    /// Re-resolves the owner and re-validates the same peer before each
    /// operation; any drift is fail-closed `OwnerLost` without retry.
    fn ensure_owner(&mut self) -> Result<&str, SsFacadeError> {
        let current = self
            .bus
            .name_owner(SECRETS_WELL_KNOWN)
            .map_err(|_| SsFacadeError::OwnerLost)?;
        if current.as_deref() != Some(self.owner.unique_name.as_str()) {
            return Err(SsFacadeError::OwnerLost);
        }
        let peer = self
            .bus
            .peer_credentials(&self.owner.unique_name)
            .map_err(|_| SsFacadeError::OwnerLost)?;
        if !self.owner.still_bound(&self.facts, peer) {
            return Err(SsFacadeError::OwnerLost);
        }
        Ok(self.owner.unique_name.as_str())
    }

    /// Test-only access to the injected bus for mid-session fixture arming.
    #[cfg(test)]
    pub const fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    fn search_entry(&mut self, identity: &EntryIdentity) -> Result<SsSearchOutcome, SsFacadeError> {
        let dest = self.ensure_owner()?.to_owned();
        let attributes = item_layout::search_attributes(identity);
        self.bus
            .search_items(&dest, &attributes)
            .map_err(unavailable)
    }

    /// Lock-state probe by exact attributes: the same unlocked-only search
    /// the reads use (never a prompt or unlock call). Ambiguity is an error.
    pub fn entry_lock_state(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<EntryLockState, SsFacadeError> {
        let outcome = self.search_entry(identity)?;
        if !outcome.locked.is_empty() {
            return Ok(EntryLockState::Locked);
        }
        if outcome.unlocked.len() > 1 {
            return Err(SsFacadeError::Ambiguous);
        }
        Ok(if outcome.unlocked.is_empty() {
            EntryLockState::Missing
        } else {
            EntryLockState::PresentUnlocked
        })
    }

    /// Reads one entry by exact attributes, unlocked-only. Locked matches are
    /// fail-closed; zero matches is `None`.
    pub fn read_entry(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SsFacadeError> {
        let outcome = self.search_entry(identity)?;
        if outcome.unlocked.len() > 1 || (outcome.unlocked.len() + outcome.locked.len()) > 1 {
            return Err(SsFacadeError::Ambiguous);
        }
        if let Some(item) = outcome.unlocked.first() {
            let dest = self.ensure_owner()?.to_owned();
            let secret = self
                .bus
                .get_secret(&dest, &self.session.session_path, item)
                .map_err(unavailable)?;
            return self.session.decrypt(&secret).map(Some).map_err(unavailable);
        }
        if outcome.locked.is_empty() {
            Ok(None)
        } else {
            Err(SsFacadeError::Locked)
        }
    }

    /// Writes one entry: updates the unique unlocked match, or creates it in
    /// the aliased collection. Locked matches or prompt demands fail closed.
    pub fn write_entry(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<(), SsFacadeError> {
        let outcome = self.search_entry(identity)?;
        if !outcome.locked.is_empty() {
            return Err(SsFacadeError::Locked);
        }
        if outcome.unlocked.len() > 1 {
            return Err(SsFacadeError::Ambiguous);
        }
        let dest = self.ensure_owner()?.to_owned();
        if let Some(item) = outcome.unlocked.first().cloned() {
            let wire = self.session.encrypt(secret, item_layout::CONTENT_TYPE);
            return match self.bus.set_item_secret(&dest, &item, wire) {
                Ok(SsMutationOutcome::Done) => Ok(()),
                Ok(SsMutationOutcome::PromptRequired) => Err(SsFacadeError::Rejected),
                Err(SsBusError::Transport) => Err(SsFacadeError::Unavailable),
            };
        }
        let collection = self
            .bus
            .read_alias(&dest, DEFAULT_COLLECTION_ALIAS)
            .map_err(unavailable)?
            .ok_or(SsFacadeError::Unavailable)?;
        let wire = self.session.encrypt(secret, item_layout::CONTENT_TYPE);
        let (_, outcome) = self
            .bus
            .create_item(
                &dest,
                &collection,
                &item_layout::label(identity),
                &item_layout::item_attributes(identity),
                wire,
                true,
            )
            .map_err(unavailable)?;
        match outcome {
            SsMutationOutcome::Done => Ok(()),
            SsMutationOutcome::PromptRequired => Err(SsFacadeError::Rejected),
        }
    }

    /// Deletes every unlocked item matching the exact attributes and reports
    /// whether any locked matches remain (fail-closed for the caller).
    pub fn delete_entry(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<SsDeletionOutcome, SsFacadeError> {
        let outcome = self.search_entry(identity)?;
        if !outcome.locked.is_empty() {
            return Err(SsFacadeError::Locked);
        }
        let dest = self.ensure_owner()?.to_owned();
        for item in &outcome.unlocked {
            match self.bus.delete_item(&dest, item) {
                Ok(SsMutationOutcome::Done) => {}
                Ok(SsMutationOutcome::PromptRequired) => return Err(SsFacadeError::Rejected),
                Err(SsBusError::Transport) => return Err(SsFacadeError::Unavailable),
            }
        }
        let remaining = self.search_entry(identity)?;
        if !remaining.unlocked.is_empty() || !remaining.locked.is_empty() {
            return Err(SsFacadeError::Rejected);
        }
        Ok(if outcome.unlocked.is_empty() {
            SsDeletionOutcome::Absent
        } else {
            SsDeletionOutcome::Deleted
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsDeletionOutcome {
    Deleted,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryLockState {
    PresentUnlocked,
    Locked,
    Missing,
}

const fn unavailable(_: SsBusError) -> SsFacadeError {
    SsFacadeError::Unavailable
}

const fn map_owner_error(error: OwnerError) -> SsFacadeError {
    match error {
        OwnerError::Unreadable | OwnerError::Invalid => SsFacadeError::OwnerInvalid,
    }
}
