use crate::model::{ControlAction, OfferAction, ReceiverModel, TargetBinding};
use crate::wire::{self, ControlKind, IdentityWire, OfferParts};

fn offer(id: u8, deadline: u64) -> crate::ProtectedHandleOffer {
    wire::encode_offer(OfferParts {
        offer_id: [id; 16],
        target_pid: 7,
        launch_generation: 9,
        identity: IdentityWire {
            volume_serial: 3,
            file_id: [4; 16],
        },
        deadline_millis: deadline,
        remote_token: 5,
        transcript: [0; 32],
    })
}

fn model() -> ReceiverModel {
    ReceiverModel::new(TargetBinding::new(7, 9).unwrap())
}

#[test]
fn commit_requires_exact_finalize_once() {
    let mut state = model();
    let frame = offer(1, 100);
    let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
        panic!()
    };
    let ready = state.ready(parts, 11).unwrap();
    let ready_parts = ready.parts().unwrap();
    assert_eq!(ready_parts.kind, ControlKind::Ready);
    assert!(matches!(
        state.control(ready_parts, 12),
        ControlAction::Nack(_)
    ));
    let final_parts = wire::finalize(parts).parts().unwrap();
    assert!(matches!(
        state.control(final_parts, 13),
        ControlAction::Commit(_)
    ));
    assert!(matches!(
        state.control(final_parts, 14),
        ControlAction::Finalize(_)
    ));
}

#[test]
fn replay_and_different_digest_never_reclone() {
    let mut state = model();
    let frame = offer(2, 100);
    let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
        panic!()
    };
    assert!(matches!(
        state.begin(&frame, 11).unwrap(),
        OfferAction::Nack(_)
    ));
    let _ = state.ready(parts, 12).unwrap();
    assert!(matches!(
        state.begin(&frame, 13).unwrap(),
        OfferAction::Ready(_)
    ));
    let changed = wire::encode_offer(OfferParts {
        remote_token: 8,
        ..parts
    });
    assert!(matches!(
        state.begin(&changed, 14).unwrap(),
        OfferAction::Nack(_)
    ));
}

#[test]
fn expiry_cancel_close_and_capacity_are_bounded() {
    let mut state = model();
    for id in 1..=64 {
        assert!(matches!(
            state.begin(&offer(id, 100), 1).unwrap(),
            OfferAction::Clone(_)
        ));
    }
    assert!(matches!(
        state.begin(&offer(65, 100), 1).unwrap(),
        OfferAction::Nack(_)
    ));
    assert_eq!(state.expire(100).len(), 64);
    let OfferAction::Clone(parts) = state.begin(&offer(66, 200), 101).unwrap() else {
        panic!()
    };
    let _ = state.ready(parts, 102).unwrap();
    assert!(state.cancel(parts.offer_id).is_some());
    assert!(state.close().is_empty());
}

#[test]
fn nack_is_terminal_and_exact_replay_is_deterministic() {
    let mut state = model();
    let frame = offer(7, 100);
    let OfferAction::Clone(parts) = state.begin(&frame, 1).unwrap() else {
        panic!()
    };
    let nack = state.reject(parts);
    assert!(matches!(
        state.begin(&frame, 2).unwrap(),
        OfferAction::Nack(_)
    ));
    assert!(matches!(
        state.control(nack.parts().unwrap(), 3),
        ControlAction::Nack(_)
    ));
}

#[test]
fn absolute_deadline_is_rejected_during_time_validation() {
    let mut state = model();
    assert!(matches!(
        state.begin(&offer(8, 30_002), 1).unwrap(),
        OfferAction::Nack(_)
    ));
    assert!(matches!(
        state.begin(&offer(9, 1), 1).unwrap(),
        OfferAction::Nack(_)
    ));
}

#[test]
fn conflicting_id_fence_survives_original_deadline_without_reclone() {
    let mut state = model();
    let frame = offer(10, 20);
    let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
        panic!()
    };
    let conflicting = wire::encode_offer(OfferParts {
        deadline_millis: 40,
        remote_token: 8,
        ..parts
    });
    assert!(matches!(
        state.begin(&conflicting, 10).unwrap(),
        OfferAction::Nack(_)
    ));
    assert!(matches!(
        state.begin(&conflicting, 21).unwrap(),
        OfferAction::Nack(_)
    ));
}

#[test]
fn delayed_finalize_cannot_use_a_conflict_extended_replay_fence() {
    let mut state = model();
    let frame = offer(12, 20);
    let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
        panic!()
    };
    let _ = state.ready(parts, 11).unwrap();
    let conflicting = wire::encode_offer(OfferParts {
        deadline_millis: 40,
        remote_token: 8,
        ..parts
    });
    assert!(matches!(
        state.begin(&conflicting, 12).unwrap(),
        OfferAction::Nack(_)
    ));
    let finalize = wire::finalize(parts).parts().unwrap();
    assert!(matches!(
        state.control(finalize, 21),
        ControlAction::Nack(_)
    ));
    assert!(matches!(
        state.begin(&conflicting, 21).unwrap(),
        OfferAction::Nack(_)
    ));
}

#[test]
fn cancel_and_close_preserve_a_conflict_tombstone_after_live_expiry() {
    for close in [false, true] {
        let mut state = model();
        let frame = offer(if close { 13 } else { 14 }, 20);
        let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
            panic!()
        };
        let _ = state.ready(parts, 11).unwrap();
        let conflicting = wire::encode_offer(OfferParts {
            deadline_millis: 40,
            remote_token: 8,
            ..parts
        });
        assert!(matches!(
            state.begin(&conflicting, 12).unwrap(),
            OfferAction::Nack(_)
        ));
        if close {
            assert_eq!(state.close(), vec![parts.offer_id]);
        } else {
            assert!(state.cancel(parts.offer_id).is_some());
        }
        assert!(matches!(
            state.begin(&conflicting, 21).unwrap(),
            OfferAction::Nack(_)
        ));
    }
}

#[test]
fn finalize_survives_cancel_close_expire_and_replay() {
    let mut state = model();
    let frame = offer(11, 100);
    let OfferAction::Clone(parts) = state.begin(&frame, 10).unwrap() else {
        panic!()
    };
    let _ = state.ready(parts, 11).unwrap();
    let finalize = wire::finalize(parts).parts().unwrap();
    assert!(matches!(
        state.control(finalize, 12),
        ControlAction::Commit(_)
    ));
    assert!(state.cancel(parts.offer_id).is_none());
    assert!(state.close().is_empty());
    assert!(state.expire(50).is_empty());
    assert!(matches!(
        state.control(finalize, 51),
        ControlAction::Finalize(_)
    ));
    assert!(matches!(
        state.begin(&frame, 52).unwrap(),
        OfferAction::Nack(_)
    ));
}
