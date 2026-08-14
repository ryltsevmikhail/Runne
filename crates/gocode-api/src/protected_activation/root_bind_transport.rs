use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize-only client carrier, consumable only from a protected result.
pub struct ProtectedRootBindTransport {
    token: zeroize::Zeroizing<String>,
    admission_digest: [u8; 32],
}

impl ProtectedRootBindTransport {
    pub(crate) fn new(
        admission: RootHandleAdmission,
        admission_digest: [u8; 32],
    ) -> Result<Self, RootHandleAdmissionTokenError> {
        (admission_digest != [0; 32])
            .then(|| admission.into_transport_token())
            .transpose()?
            .map(|token| Self { token: zeroize::Zeroizing::new(token), admission_digest })
            .ok_or(RootHandleAdmissionTokenError::Invalid)
    }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] { self.admission_digest }
}

impl Serialize for ProtectedRootBindTransport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(self.token.as_str()) }
}
impl std::fmt::Debug for ProtectedRootBindTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("ProtectedRootBindTransport([REDACTED])") }
}

/// Deserialize-only HTTP carrier. Authentication remains daemon-owned.
pub struct RootBindAdmission(RootHandleAdmission);
impl RootBindAdmission {
    pub fn into_admission(self) -> RootHandleAdmission { self.0 }
}
impl<'de> Deserialize<'de> for RootBindAdmission {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = String::deserialize(deserializer)?;
        RootHandleAdmission::from_transport_token(&token).map(Self).map_err(serde::de::Error::custom)
    }
}
impl std::fmt::Debug for RootBindAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("RootBindAdmission([REDACTED])") }
}

#[cfg(test)]
mod root_bind_transport_tests {
    #[test]
    fn server_carrier_cannot_promote_into_protected_provenance() {
        let production = include_str!("root_bind_transport.rs").split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("ProtectedRootHandleAdmission"));
        assert!(!production.contains("IssuedRootHandleAdmission"));
    }
}
