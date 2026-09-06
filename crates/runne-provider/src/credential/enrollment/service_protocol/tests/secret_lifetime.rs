use zeroize::Zeroizing;

use super::super::{
    CredentialMaterial, CredentialServiceProtocolCodec, CredentialServiceReply,
    CredentialServiceRequest,
};
use super::read_support::read_requests;

const CANARY: &[u8] = b"runne-d1-1c-zeroizing-codec-canary";

#[test]
fn credential_service_point_of_use_reply_decodes_into_zeroizing_material() {
    let (_, point_of_use) = read_requests("provider-1", 1);
    let context = CredentialServiceRequest::PointOfUseRead(point_of_use).context();
    let material = CredentialMaterial::from_zeroizing(Zeroizing::new(CANARY.to_vec())).unwrap();
    let encoded = CredentialServiceProtocolCodec::encode_reply(
        context,
        CredentialServiceReply::Material(material),
    )
    .unwrap();

    let CredentialServiceReply::Material(decoded) =
        CredentialServiceProtocolCodec::decode_runtime_reply(encoded.test_bytes(), context)
            .unwrap()
    else {
        panic!("expected point-of-use material");
    };
    let decoded: Zeroizing<Vec<u8>> = decoded.into_zeroizing();

    assert_eq!(decoded.as_slice(), CANARY);
}
