const CREDENTIAL_STATUS_REQUEST_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-status/request/v2";
const CREDENTIAL_STATUS_ACK_DOMAIN_V2: &[u8] = b"gocode/credential-enrollment-status/ack/v2";
const CREDENTIAL_STATUS_REQUEST_BINDING_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-status/request-binding/v2";

include!("credential_status_v2/request.rs");
include!("credential_status_v2/claims.rs");
include!("credential_status_v2/ack.rs");
