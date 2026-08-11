#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeMap;

use crate::clock::MAX_OFFER_MILLIS;
use crate::protocol::ProtocolError;
use crate::wire::{
    self, ControlKind, ControlParts, HandleFinalize, HandleNack, OfferParts, ProtectedHandleOffer,
};

const MAX_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TargetBinding {
    pub(super) pid: u32,
    pub(super) launch_generation: u64,
}

impl TargetBinding {
    pub(super) const fn new(pid: u32, launch_generation: u64) -> Result<Self, ProtocolError> {
        if pid == 0 || launch_generation == 0 {
            return Err(ProtocolError::Rejected);
        }
        Ok(Self {
            pid,
            launch_generation,
        })
    }
}

pub(super) enum OfferAction {
    Clone(OfferParts),
    Ready(crate::wire::HandleAckReady),
    Nack(HandleNack),
}

pub(super) enum ControlAction {
    Commit([u8; 16]),
    Drop([u8; 16]),
    Finalize(HandleFinalize),
    Nack(HandleNack),
}

pub(super) struct ReceiverModel {
    binding: TargetBinding,
    pub(super) entries: BTreeMap<[u8; 16], Entry>,
}

pub(super) enum Entry {
    Staging {
        parts: OfferParts,
        replay_fence_deadline: u64,
    },
    Ready {
        parts: OfferParts,
        replay_fence_deadline: u64,
    },
    Terminal {
        parts: OfferParts,
        kind: TerminalKind,
        replay_fence_deadline: u64,
    },
}

#[derive(Clone, Copy)]
pub(super) enum TerminalKind {
    Finalize,
    Nack,
}

impl ReceiverModel {
    pub(super) const fn new(binding: TargetBinding) -> Self {
        Self {
            binding,
            entries: BTreeMap::new(),
        }
    }

    pub(super) fn begin(
        &mut self,
        offer: &ProtectedHandleOffer,
        now: u64,
    ) -> Result<OfferAction, ProtocolError> {
        let parts = offer.parts()?;
        if parts.target_pid != self.binding.pid
            || parts.launch_generation != self.binding.launch_generation
        {
            return Ok(OfferAction::Nack(wire::nack(parts)));
        }
        if parts.deadline_millis <= now || parts.deadline_millis - now > MAX_OFFER_MILLIS {
            return Ok(OfferAction::Nack(wire::nack(parts)));
        }
        self.purge_expired(now);
        if let Some(existing) = self.entries.get_mut(&parts.offer_id) {
            return Ok(replay(existing, parts));
        }
        if self.entries.len() >= MAX_RECORDS {
            return Ok(OfferAction::Nack(wire::nack(parts)));
        }
        self.entries.insert(
            parts.offer_id,
            Entry::Staging {
                parts,
                replay_fence_deadline: parts.deadline_millis,
            },
        );
        Ok(OfferAction::Clone(parts))
    }

    pub(super) fn ready(
        &mut self,
        parts: OfferParts,
        now: u64,
    ) -> Result<crate::wire::HandleAckReady, ProtocolError> {
        if parts.deadline_millis <= now {
            self.terminal(parts, TerminalKind::Nack);
            return Err(ProtocolError::Rejected);
        }
        let Some(Entry::Staging { parts: staged, .. }) = self.entries.get(&parts.offer_id) else {
            return Err(ProtocolError::Rejected);
        };
        if staged.transcript != parts.transcript {
            return Err(ProtocolError::Rejected);
        }
        let replay_fence_deadline = replay_fence_deadline(
            self.entries
                .get(&parts.offer_id)
                .ok_or(ProtocolError::Rejected)?,
        );
        self.entries.insert(
            parts.offer_id,
            Entry::Ready {
                parts,
                replay_fence_deadline,
            },
        );
        Ok(wire::ready(parts))
    }

    pub(super) fn reject(&mut self, parts: OfferParts) -> HandleNack {
        self.terminal(parts, TerminalKind::Nack);
        wire::nack(parts)
    }

    pub(super) fn control(&mut self, control: ControlParts, now: u64) -> ControlAction {
        self.purge_expired(now);
        let Some(entry) = self.entries.get(&control.offer_id) else {
            return ControlAction::Nack(wire::nack_from_control(control));
        };
        let parts = parts(entry);
        if parts.transcript != control.transcript {
            return ControlAction::Nack(wire::nack_from_control(control));
        }
        match entry {
            Entry::Ready { .. }
                if control.kind == ControlKind::Finalize && parts.deadline_millis > now =>
            {
                self.entries.insert(
                    control.offer_id,
                    Entry::Terminal {
                        parts,
                        kind: TerminalKind::Finalize,
                        replay_fence_deadline: replay_fence_deadline(entry),
                    },
                );
                ControlAction::Commit(control.offer_id)
            }
            Entry::Ready { .. } if control.kind == ControlKind::Nack => {
                self.entries.insert(
                    control.offer_id,
                    Entry::Terminal {
                        parts,
                        kind: TerminalKind::Nack,
                        replay_fence_deadline: replay_fence_deadline(entry),
                    },
                );
                ControlAction::Drop(control.offer_id)
            }
            Entry::Terminal {
                kind: TerminalKind::Finalize,
                ..
            } => ControlAction::Finalize(wire::finalize(parts)),
            _ => ControlAction::Nack(wire::nack(parts)),
        }
    }

    pub(super) fn cancel(&mut self, offer_id: [u8; 16]) -> Option<HandleNack> {
        let entry = self.entries.get(&offer_id)?;
        let parts = parts(entry);
        if matches!(entry, Entry::Terminal { .. }) {
            return None;
        }
        self.terminal(parts, TerminalKind::Nack);
        Some(wire::nack(parts))
    }

    pub(super) fn close(&mut self) -> Vec<[u8; 16]> {
        let ids = self
            .entries
            .iter()
            .filter_map(|(id, entry)| (!matches!(entry, Entry::Terminal { .. })).then_some(*id))
            .collect::<Vec<_>>();
        for id in &ids {
            if let Some(parts) = self.entries.get(id).map(parts) {
                self.terminal(parts, TerminalKind::Nack);
            }
        }
        ids
    }

    fn purge_expired(&mut self, now: u64) {
        let _ = self.expire(now);
    }

    fn terminal(&mut self, parts: OfferParts, kind: TerminalKind) {
        let replay_fence_deadline = self
            .entries
            .get(&parts.offer_id)
            .map_or(parts.deadline_millis, replay_fence_deadline);
        self.entries.insert(
            parts.offer_id,
            Entry::Terminal {
                parts,
                kind,
                replay_fence_deadline,
            },
        );
    }
}

fn replay(entry: &mut Entry, incoming: OfferParts) -> OfferAction {
    let existing = parts(entry);
    if existing.transcript != incoming.transcript {
        extend_fence(entry, incoming.deadline_millis);
        return OfferAction::Nack(wire::nack(incoming));
    }
    match entry {
        Entry::Ready { .. } => OfferAction::Ready(wire::ready(existing)),
        Entry::Staging { .. } | Entry::Terminal { .. } => OfferAction::Nack(wire::nack(existing)),
    }
}

const fn parts(entry: &Entry) -> OfferParts {
    match entry {
        Entry::Staging { parts, .. }
        | Entry::Ready { parts, .. }
        | Entry::Terminal { parts, .. } => *parts,
    }
}

pub(super) const fn replay_fence_deadline(entry: &Entry) -> u64 {
    match entry {
        Entry::Staging {
            replay_fence_deadline,
            ..
        }
        | Entry::Ready {
            replay_fence_deadline,
            ..
        }
        | Entry::Terminal {
            replay_fence_deadline,
            ..
        } => *replay_fence_deadline,
    }
}

fn extend_fence(entry: &mut Entry, deadline: u64) {
    match entry {
        Entry::Staging {
            replay_fence_deadline,
            ..
        }
        | Entry::Ready {
            replay_fence_deadline,
            ..
        }
        | Entry::Terminal {
            replay_fence_deadline,
            ..
        } => {
            *replay_fence_deadline = (*replay_fence_deadline).max(deadline);
        }
    }
}
