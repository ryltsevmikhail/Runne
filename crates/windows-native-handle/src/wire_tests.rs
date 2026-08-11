use crate::wire::{self, CONTROL_BYTES, IdentityWire, OFFER_BYTES, OfferParts};
use crate::{HandleAckReady, ProtectedHandleOffer, ProtocolError};

fn offer() -> ProtectedHandleOffer {
    wire::encode_offer(OfferParts {
        offer_id: [1; 16],
        target_pid: 2,
        launch_generation: 3,
        identity: IdentityWire {
            volume_serial: 4,
            file_id: [5; 16],
        },
        deadline_millis: 123_456_789,
        remote_token: 6,
        transcript: [0; 32],
    })
}

#[test]
fn fixed_frame_corpus_is_structural_before_time_validation() {
    let valid_offer = offer();
    assert_eq!(valid_offer.into_protected_bytes().len(), OFFER_BYTES);
    let bytes = offer().into_protected_bytes();
    assert_eq!(
        ProtectedHandleOffer::from_protected_bytes(bytes)
            .unwrap()
            .parts()
            .unwrap()
            .deadline_millis,
        123_456_789
    );
    let mut bad_magic = bytes;
    bad_magic[0] = b'X';
    assert!(matches!(
        ProtectedHandleOffer::from_protected_bytes(bad_magic),
        Err(ProtocolError::Rejected)
    ));
    let mut bad_digest = bytes;
    bad_digest[71] ^= 1;
    assert!(matches!(
        ProtectedHandleOffer::from_protected_bytes(bad_digest),
        Err(ProtocolError::Rejected)
    ));
    let ready = wire::ready(offer().parts().unwrap()).into_protected_bytes();
    assert_eq!(ready.len(), CONTROL_BYTES);
    let mut reserved = ready;
    reserved[63] = 1;
    assert!(matches!(
        HandleAckReady::from_protected_bytes(reserved),
        Err(ProtocolError::Rejected)
    ));
}
