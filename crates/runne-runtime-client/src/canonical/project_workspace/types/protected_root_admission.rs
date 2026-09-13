/// Move-only runtime boundary over a verified protected host transfer.
pub struct ProtectedRootAdmission(ProtectedRootBindTransport);
impl std::fmt::Debug for ProtectedRootAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedRootAdmission([REDACTED])")
    }
}
impl ProtectedRootAdmission {
    pub fn from_verified(value: ProtectedRootHandleAdmission) -> Result<Self, RuntimeApiError> {
        value
            .into_root_bind_transport()
            .map(Self)
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))
    }
    pub(crate) const fn transport(&self) -> &ProtectedRootBindTransport {
        &self.0
    }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] {
        self.0.admission_digest()
    }
}
#[derive(Debug)]
pub struct BindWorkspaceRootRequest<'a> {
    pub(super) identity: CommandIdentity,
    pub(super) id: CanonicalId,
    pub(super) expected_version: u64,
    pub(super) admission: &'a ProtectedRootAdmission,
}
impl<'a> BindWorkspaceRootRequest<'a> {
    pub fn new(
        identity: CommandIdentity,
        id: CanonicalId,
        expected_version: u64,
        admission: &'a ProtectedRootAdmission,
    ) -> Result<Self, RuntimeApiError> {
        version(expected_version)?;
        Ok(Self {
            identity,
            id,
            expected_version,
            admission,
        })
    }
}
