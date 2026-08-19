use base64::Engine;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_security::SecretBroker;

const MARKER: &[u8] = b"inert-secret-marker-\xfb\xff";

fn assert_prohibited(disposition: ContentDisposition) {
    assert!(matches!(disposition, ContentDisposition::Prohibited { .. }));
}

#[test]
fn rejects_registered_non_empty_value_and_exact_encodings() {
    let marker = MARKER;
    let mut broker = SecretBroker::new();
    broker.register("test marker", marker.to_vec()).unwrap();
    let guard = broker.prohibited_content_guard();

    let standard = base64::engine::general_purpose::STANDARD.encode(marker);
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(marker);
    assert_ne!(standard.trim_end_matches('='), url_safe);
    let cases = [
        marker.to_vec(),
        standard.as_bytes().to_vec(),
        standard.trim_end_matches('=').as_bytes().to_vec(),
        url_safe.into_bytes(),
        hex::encode(marker).into_bytes(),
        hex::encode_upper(marker).into_bytes(),
    ];

    for bytes in cases {
        assert_prohibited(
            guard
                .inspect(CanonicalContentBoundary::CanonicalMutation, &bytes)
                .unwrap(),
        );
    }
}

#[test]
fn allows_unregistered_credential_looking_text() {
    let guard = SecretBroker::new().prohibited_content_guard();
    assert!(matches!(
        guard
            .inspect(
                CanonicalContentBoundary::CanonicalMutation,
                b"sk-looks-like-a-credential-but-is-not-registered",
            )
            .unwrap(),
        ContentDisposition::Allowed { .. }
    ));
}

#[test]
fn matcher_width_tracks_active_secret_representations() {
    let mut broker = SecretBroker::new();
    assert_eq!(
        broker
            .prohibited_content_guard()
            .maximum_match_len()
            .unwrap(),
        1
    );

    broker
        .register("test marker", MARKER.to_vec())
        .expect("fixture registration must succeed");
    assert!(
        broker
            .prohibited_content_guard()
            .maximum_match_len()
            .unwrap()
            >= MARKER.len()
    );
}

#[test]
fn revoked_values_no_longer_match_after_epoch_advances() {
    let marker = MARKER;
    let mut broker = SecretBroker::new();
    let secret_ref = broker.register("test marker", marker.to_vec()).unwrap();
    let guard = broker.prohibited_content_guard();
    let before = guard
        .inspect(CanonicalContentBoundary::CanonicalMutation, marker)
        .unwrap();
    broker.revoke(&secret_ref).unwrap();
    let after = guard
        .inspect(CanonicalContentBoundary::CanonicalMutation, marker)
        .unwrap();

    assert_prohibited(before);
    assert!(matches!(after, ContentDisposition::Allowed { .. }));
    let ContentDisposition::Prohibited {
        policy_epoch: before_epoch,
    } = before
    else {
        unreachable!();
    };
    let ContentDisposition::Allowed {
        policy_epoch: after_epoch,
    } = after
    else {
        unreachable!();
    };
    assert!(after_epoch > before_epoch);
}

#[test]
fn typed_secret_value_is_rejected_without_materializing_it() {
    let mut broker = SecretBroker::new();
    let secret_ref = broker.register("test marker", MARKER.to_vec()).unwrap();
    let handle = broker.resolve(&secret_ref, true).unwrap();
    let guard = broker.prohibited_content_guard();

    assert_prohibited(
        guard
            .inspect_secret_value(
                CanonicalContentBoundary::OutboundDelivery,
                handle.as_secret_value(),
            )
            .unwrap(),
    );
}
