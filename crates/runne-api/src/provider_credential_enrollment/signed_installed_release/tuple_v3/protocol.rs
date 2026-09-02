use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3ProtocolCompatibility {
    registration_wire: u16,
    registration_auth_suite: u16,
    provider_frame_wire: u16,
    provider_grant_auth: u16,
    runtime_envelope_wire: u16,
    runtime_request_auth: u16,
    runtime_reply_auth: u16,
}

impl NativeEnrollmentTupleV3ProtocolCompatibility {
    pub const fn new(
        registration_wire: u16,
        registration_auth_suite: u16,
        provider_frame_wire: u16,
        provider_grant_auth: u16,
        runtime_envelope_wire: u16,
        runtime_request_auth: u16,
        runtime_reply_auth: u16,
    ) -> Self {
        Self {
            registration_wire,
            registration_auth_suite,
            provider_frame_wire,
            provider_grant_auth,
            runtime_envelope_wire,
            runtime_request_auth,
            runtime_reply_auth,
        }
    }

    pub(super) const fn values(self) -> [u16; 7] {
        [
            self.registration_wire,
            self.registration_auth_suite,
            self.provider_frame_wire,
            self.provider_grant_auth,
            self.runtime_envelope_wire,
            self.runtime_request_auth,
            self.runtime_reply_auth,
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV3ProtocolVersions {
    compatibility_bundles: Vec<NativeEnrollmentTupleV3ProtocolCompatibility>,
}

impl NativeEnrollmentTupleV3ProtocolVersions {
    pub const fn new(
        compatibility_bundles: Vec<NativeEnrollmentTupleV3ProtocolCompatibility>,
    ) -> Self {
        Self {
            compatibility_bundles,
        }
    }

    pub fn compatibility_bundles(
        &self,
    ) -> impl Iterator<Item = NativeEnrollmentTupleV3ProtocolCompatibility> + '_ {
        self.compatibility_bundles.iter().copied()
    }

    pub(super) fn valid(&self) -> bool {
        (1..=16).contains(&self.compatibility_bundles.len())
            && self
                .compatibility_bundles
                .iter()
                .all(|bundle| bundle.values().into_iter().all(|version| version != 0))
            && self
                .compatibility_bundles
                .windows(2)
                .all(|pair| pair[0] < pair[1])
    }
}
