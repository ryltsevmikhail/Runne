use super::super::*;
use runne_api::ApiPrincipalId;
use runne_domain::id::ProjectId;
use std::io::{Seek, SeekFrom, Write};

pub(super) const AUTH: &str = "01800000000070008000000000000001";
pub(super) const PROJECT: &str = "01800000000070008000000000000002";
pub(super) const MCP: &str = r#"{"kind":"mcp","id":"local-tools","record_revision":2,"transport":"local_contained","required_profile":{"id":"sdk-required","revision":1}}"#;
pub(super) const REMOTE: &str = r#"{"kind":"mcp","id":"remote-tools","record_revision":2,"transport":"remote_brokered","required_profile":{"id":"sdk-required","revision":1}}"#;
pub(super) const PLUGIN: &str = r#"{"kind":"plugin","id":"formatter","record_revision":3,"package":{"version":"1.0.0","digest":"1111111111111111111111111111111111111111111111111111111111111111"}}"#;
pub(super) fn json() -> String {
    document(&format!(
        "{},{},{},{}",
        PLUGIN,
        REMOTE,
        PLUGIN.replace("formatter", "linter"),
        MCP
    ))
}
pub(super) fn document(records: &str) -> String {
    format!(
        r#"{{"schema_version":1,"authority_id":"{AUTH}","principal_id":"fixture-owner","project_id":"{PROJECT}","registration_revision":7,"registrations":[{records}]}}"#
    )
}
pub(super) fn scope() -> RegistryScope {
    RegistryScope {
        authority_id: hex::decode(AUTH).unwrap().try_into().unwrap(),
        principal: ApiPrincipalId::new("fixture-owner").unwrap(),
        project: ProjectId::from_bytes(hex::decode(PROJECT).unwrap().try_into().unwrap()),
        runtime_incarnation: [1; 16],
        runtime_generation: 1,
    }
}
pub(super) fn version() -> SnapshotVersion {
    SnapshotVersion {
        schema_version: 1,
        registration_revision: 7,
        metadata_digest: super::vectors::DIGEST,
    }
}
pub(super) fn expected() -> RegistryExpectation {
    RegistryExpectation {
        scope: scope(),
        version: version(),
    }
}
pub(super) fn request() -> QueryRequest {
    let s = scope();
    QueryRequest {
        context: QueryContext {
            principal: s.principal,
            project: s.project,
            runtime_incarnation: s.runtime_incarnation,
            runtime_generation: 1,
            owner_epoch: 1,
            contract_version: 1,
        },
        expected_snapshot: version(),
        query: Query::List { kind: None },
    }
}
pub(super) fn key(kind: ExtensionKind, id: &str) -> ExtensionKey {
    ExtensionKey {
        kind,
        id: RegistrationId(id.into()),
    }
}
pub(super) fn file(bytes: &[u8]) -> std::fs::File {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f
}
pub(super) fn capture(text: &str) -> Result<ConfiguredExtensionRegistry, MetadataQueryError> {
    ConfiguredExtensionRegistry::capture(file(text.as_bytes()), expected())
}
pub(super) fn expected_for(text: &str) -> RegistryExpectation {
    // Varied fixtures use production normalization; the baseline oracle is independent vectors.rs.
    let mut e = expected();
    let records = super::super::storage_header::parse(text.as_bytes())
        .unwrap()
        .normalize()
        .unwrap();
    e.version.metadata_digest = super::super::digest::metadata_digest(&e.scope, 7, &records);
    e
}
pub(super) fn reject(text: &str, error: MetadataQueryError) {
    assert_eq!(capture(text).unwrap_err(), error, "unexpected closed error");
}
