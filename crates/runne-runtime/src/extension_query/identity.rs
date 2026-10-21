use runne_api::ApiPrincipalId;
use runne_domain::id::ProjectId;

macro_rules! opaque {
    ($($t:ty),+ $(,)?) => { $(impl std::fmt::Debug for $t {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($t), "(<opaque>)"))
        }
    })+ };
}
pub(super) use opaque;
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RegistryScope {
    pub(super) authority_id: [u8; 16],
    pub(super) principal: ApiPrincipalId,
    pub(super) project: ProjectId,
    pub(super) runtime_incarnation: [u8; 16],
    pub(super) runtime_generation: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct SnapshotVersion {
    pub(super) schema_version: u16,
    pub(super) registration_revision: u64,
    pub(super) metadata_digest: [u8; 32],
}
#[derive(Clone)]
pub(super) struct RegistryExpectation {
    pub(super) scope: RegistryScope,
    pub(super) version: SnapshotVersion,
}
#[derive(Clone)]
pub(super) struct QueryContext {
    pub(super) principal: ApiPrincipalId,
    pub(super) project: ProjectId,
    pub(super) runtime_incarnation: [u8; 16],
    pub(super) runtime_generation: u64,
    pub(super) owner_epoch: u64,
    pub(super) contract_version: u16,
}
#[derive(Clone)]
pub(super) struct QueryRequest {
    pub(super) context: QueryContext,
    pub(super) expected_snapshot: SnapshotVersion,
    pub(super) query: super::record::Query,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RegistrationId(pub(super) String);
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ProfileId(pub(super) String);
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PackageVersion(pub(super) String);
pub(super) const EPOCH_CAP: u64 = i64::MAX as u64;
pub(super) fn bounded_revision(n: u64) -> bool {
    (1..=EPOCH_CAP).contains(&n)
}
pub(super) fn valid_uuid(bytes: &[u8; 16]) -> bool {
    runne_domain::id::validate_uuid_v7_bytes(bytes).is_ok()
}
pub(super) fn valid_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
pub(super) fn valid_semver(s: &str) -> bool {
    if s.len() > 64 || !s.is_ascii() {
        return false;
    }
    let parts: Vec<_> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && (p.len() == 1 || !p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok()
        })
}
pub(super) fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], super::MetadataQueryError> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(super::MetadataQueryError::InvalidSnapshot);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(s, &mut bytes).map_err(|_| super::MetadataQueryError::InvalidSnapshot)?;
    Ok(bytes)
}
impl RegistryExpectation {
    pub(super) fn validate(&self) -> Result<(), super::MetadataQueryError> {
        if !valid_uuid(&self.scope.authority_id)
            || !valid_uuid(self.scope.project.as_bytes())
            || self.scope.runtime_incarnation == [0; 16]
            || !bounded_revision(self.scope.runtime_generation)
            || !bounded_revision(self.version.registration_revision)
            || ApiPrincipalId::new(self.scope.principal.as_str()).is_err()
        {
            return Err(super::MetadataQueryError::InvalidRequest);
        }
        if self.version.schema_version != 1 {
            return Err(super::MetadataQueryError::UnsupportedContract);
        }
        Ok(())
    }
}
opaque!(
    RegistryScope,
    SnapshotVersion,
    RegistryExpectation,
    QueryContext,
    QueryRequest,
    RegistrationId,
    ProfileId,
    PackageVersion
);
