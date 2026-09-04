use crate::{
    CredentialServiceIngressRequest, CredentialServiceProtocolCodec, CredentialServiceRequestFrame,
};

pub(super) fn assert_revision_roundtrip(encoded: &CredentialServiceRequestFrame) {
    let bytes = encoded.test_bytes();
    let CredentialServiceIngressRequest::WriterConsume(request) =
        CredentialServiceProtocolCodec::decode_writer_request(bytes).unwrap()
    else {
        panic!("expected writer request");
    };
    let (_, _, material, revision) = request.into_parts();
    assert_eq!(revision, Some([73; 16]));
    material
        .unwrap()
        .consume(|bytes| assert_eq!(bytes, &[72; 32]));

    let mut missing = bytes[..bytes.len() - 16].to_vec();
    missing[14] = 3; // Published pre-revision WriterConsume vocabulary.
    let length = u32::try_from(missing.len() - 14).unwrap();
    missing[10..14].copy_from_slice(&length.to_be_bytes());
    assert!(CredentialServiceProtocolCodec::decode_writer_request(&missing).is_err());
    let mut zero = bytes.to_vec();
    let end = zero.len();
    zero[end - 16..].fill(0);
    assert!(CredentialServiceProtocolCodec::decode_writer_request(&zero).is_err());
    assert!(CredentialServiceProtocolCodec::decode_runtime_request(bytes).is_err());
}
