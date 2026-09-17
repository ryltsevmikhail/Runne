include!("local_session/profile.rs");
include!("local_session/profile_v3.rs");
mod bootstrap_v3;
use bootstrap_v3::{
    AuthenticateRequest, AuthenticateResponse, BootstrapWindow, ChallengeRequest,
    ChallengeResponse, final_transcript, key_version, preallocation_transcript, wire_version,
};
include!("local_session/connect.rs");
include!("local_session/wire.rs");
include!("local_session/tests.rs");
#[cfg(test)]
include!("local_session/v3_tests.rs");
#[cfg(test)]
include!("local_session/v3_capability_tests.rs");
#[cfg(test)]
include!("local_session/v3_remote_tests.rs");
