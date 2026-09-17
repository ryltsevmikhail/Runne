/// Move-only runtime boundary over a verified protected host transfer.
pub struct ProtectedRootAdmission {
    transport: ProtectedRootBindTransport,
    workspace_id: CanonicalId,
    expected_version: u64,
    admission_digest: [u8; 32],
}
impl std::fmt::Debug for ProtectedRootAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedRootAdmission([REDACTED])")
    }
}
impl ProtectedRootAdmission {
    pub fn from_verified(value: ProtectedRootHandleAdmission) -> Result<Self, RuntimeApiError> {
        let workspace_id = CanonicalId::try_from(value.workspace_id())?;
        let expected_version = value.expected_version();
        let admission_digest = value.admission_digest();
        if expected_version == 0 || admission_digest == [0; 32] {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        let transport = value
            .into_root_bind_transport()
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        if transport.admission_digest() != admission_digest {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self {
            transport,
            workspace_id,
            expected_version,
            admission_digest,
        })
    }
    pub(crate) const fn transport(&self) -> &ProtectedRootBindTransport {
        &self.transport
    }
    #[must_use]
    pub const fn workspace_id(&self) -> CanonicalId {
        self.workspace_id
    }
    #[must_use]
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }
    #[must_use]
    pub const fn admission_digest(&self) -> [u8; 32] {
        self.admission_digest
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
        if id != admission.workspace_id() || expected_version != admission.expected_version() {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
        }
        Ok(Self {
            identity,
            id,
            expected_version,
            admission,
        })
    }
}
