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
    assert_eq!(state.close().len(), 1);
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
