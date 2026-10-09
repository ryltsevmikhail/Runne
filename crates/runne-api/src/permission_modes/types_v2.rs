use serde::{Deserialize, Deserializer, Serialize};

/// V2 containment labels use camelCase while the V1 labels remain frozen.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionContainmentV2 {
    WorkspaceBoundV1,
    SameUserCompositeV1,
    SameUserCompositeV2,
}

/// Network posture distinguishes deliberate denial from missing enforcement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionNetworkStateV2 {
    None,
    Brokered,
    BroadSameUser,
    Unavailable,
}

/// Freshness of one captured observation, not an authorization revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionModeLifecycleV2 {
    Current,
    Stale,
    Revoked,
    Reconciling,
}

/// Reasons that the complete effective projection cannot currently be ready.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionModeNotReadyReasonV2 {
    NativeContainmentUnavailable,
    CompositePolicyUnenforceable,
    PresetUnavailable,
    StaleObservation,
    Revoked,
    Reconciling,
    SourceProvenanceUnavailable,
    ProtectedResourceSafetyUnavailable,
}

/// Forces nullable wire fields to be present while still accepting explicit null.
pub(crate) fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
