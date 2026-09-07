//! Downstream module paths and decoder error precedence survive source moves.
use runne_inference_protocol::backend_codec::decode_worker_body;
use runne_inference_protocol::codec::{ProtocolBody, decode_body, encode_body};
use runne_inference_protocol::{Cbor, MessageV1, ProtocolError};

#[test]
fn public_codec_module_round_trips_engine_messages() {
    let message = MessageV1::Health;
    let body = encode_body(&message);
    assert_eq!(body, ProtocolBody::encode_body(&message));
    assert_eq!(decode_body(message.type_name(), &body), Ok(message));
}

#[test]
fn worker_decoder_rejects_non_map_before_unknown_type() {
    let body = Cbor::Unsigned(0);
    for type_name in ["unknown", "backend_health"] {
        assert!(matches!(
            decode_worker_body(type_name, &body),
            Err(ProtocolError::Malformed)
        ));
    }
    let empty_map = Cbor::Map(Default::default());
    assert!(matches!(
        decode_worker_body("unknown", &empty_map),
        Err(ProtocolError::UnknownType)
    ));
    assert!(matches!(
        decode_worker_body("backend_health", &empty_map),
        Err(ProtocolError::UnknownField)
    ));
}
