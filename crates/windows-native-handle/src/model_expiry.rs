#![allow(clippy::redundant_pub_crate)]

use crate::model::{Entry, ReceiverModel, TerminalKind, replay_fence_deadline};

impl ReceiverModel {
    pub(super) fn expire(&mut self, now: u64) -> Vec<[u8; 16]> {
        let transitions = self
            .entries
            .iter()
            .filter_map(|(id, entry)| match entry {
                Entry::Staging {
                    parts,
                    replay_fence_deadline,
                }
                | Entry::Ready {
                    parts,
                    replay_fence_deadline,
                } if parts.deadline_millis <= now => Some((*id, *parts, *replay_fence_deadline)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let removals = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                matches!(entry, Entry::Terminal { .. })
                    .then(|| replay_fence_deadline(entry) <= now)
                    .filter(|expired| *expired)
                    .map(|_| *id)
            })
            .collect::<Vec<_>>();
        for (id, parts, replay_fence_deadline) in &transitions {
            self.entries.insert(
                *id,
                Entry::Terminal {
                    parts: *parts,
                    kind: TerminalKind::Nack,
                    replay_fence_deadline: *replay_fence_deadline,
                },
            );
        }
        for id in removals {
            self.entries.remove(&id);
        }
        transitions.into_iter().map(|(id, _, _)| id).collect()
    }
}
