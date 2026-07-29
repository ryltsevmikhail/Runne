//! Inventory entry — full route metadata. Std-only, zero deps.

use std::sync::LazyLock;

use crate::classify::{CompatibilityClass, Confidence, ImplementationStatus, RejectionRationale};
use crate::profile::{OperationSelector, Transport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    pub inventory_id: String,
    pub upstream_operation_id: Option<String>,
    pub selector: OperationSelector,
    pub transport: Transport,
    pub request_schema_ref: SchemaRef,
    pub success_schema_ref: SchemaRef,
    pub error_schema_refs: Vec<SchemaRef>,
    pub stream_semantics: Option<StreamSemantics>,
    pub auth_scope: AuthScope,
    pub side_effects: Vec<SideEffect>,
    pub source: SourceRef,
    pub confidence: Confidence,
    pub classification: CompatibilityClass,
    pub implementation_status: ImplementationStatus,
    pub rationale: Option<RejectionRationale>,
    pub supported_fields: Vec<String>,
    pub unsupported_fields: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRef {
    pub path: String,
    pub digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub path: String,
    pub lines: (u32, u32),
    pub sha: String,
    pub observed_date: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSemantics {
    pub stream_type: String,
    pub event_types: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthScope {
    Session,
    System,
    User,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SideEffect {
    MutatesState,
    EmitsEvent,
    SendsHttpPush,
    WritesLog,
}

pub static INVENTORY: LazyLock<Vec<InventoryEntry>> = LazyLock::new(|| {
    vec![
        InventoryEntry {
            inventory_id: "session.create".into(),
            upstream_operation_id: Some("session.create".into()),
            selector: OperationSelector {
                transport: Transport::HTTP,
                method: "POST".into(),
                normalized_path: "/session".into(),
            },
            transport: Transport::HTTP,
            request_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            success_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::System,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "session.ts".into(),
                lines: (0, 0),
                sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec!["title".into(), "workspaceID".into()],
            unsupported_fields: vec![
                "parentID".into(),
                "agent".into(),
                "model".into(),
                "metadata".into(),
                "permission".into(),
            ],
        },
        InventoryEntry {
            inventory_id: "session.prompt".into(),
            upstream_operation_id: Some("session.prompt".into()),
            selector: OperationSelector {
                transport: Transport::HTTP,
                method: "POST".into(),
                normalized_path: "/session/:sessionID/message".into(),
            },
            transport: Transport::HTTP,
            request_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1message/post/requestBody".into(),
                digest: "sha256:9660f4c18156783f481a9743370462fb9ac7b68edc3f11a8441ea7002e1252f3".into(),
            },
            success_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1message/post/responses/200".into(),
                digest: "sha256:dadd1246f1d693236181c9fdb6ada30a215cd3b17f9b545f254e893d5f2358ea".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "packages/sdk/openapi.json".into(),
                lines: (6202, 6359),
                sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec![
                "messageID".into(),
                "parts[].type=text".into(),
                "parts[].text".into(),
            ],
            unsupported_fields: vec![
                "model".into(),
                "agent".into(),
                "noReply".into(),
                "tools".into(),
                "format".into(),
                "system".into(),
                "variant".into(),
                "non-text parts".into(),
            ],
        },
        InventoryEntry {
            inventory_id: "session.prompt_async".into(),
            upstream_operation_id: Some("session.prompt_async".into()),
            selector: OperationSelector {
                transport: Transport::HTTP,
                method: "POST".into(),
                normalized_path: "/session/:sessionID/prompt_async".into(),
            },
            transport: Transport::HTTP,
            request_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1prompt_async/post/requestBody".into(),
                digest: "sha256:9660f4c18156783f481a9743370462fb9ac7b68edc3f11a8441ea7002e1252f3".into(),
            },
            success_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1prompt_async/post/responses/204".into(),
                digest: "sha256:e97df8825be7e45d6bcb9e015d4372919d158ab5661e9941c9ab99f9b3775aa4".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "packages/sdk/openapi.json".into(),
                lines: (7102, 7241),
                sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec![
                "messageID".into(),
                "parts[].type=text".into(),
                "parts[].text".into(),
            ],
            unsupported_fields: vec![
                "model".into(),
                "agent".into(),
                "noReply".into(),
                "tools".into(),
                "format".into(),
                "system".into(),
                "variant".into(),
                "non-text parts".into(),
            ],
        },
        InventoryEntry {
            inventory_id: "session.status".into(),
            upstream_operation_id: Some("session.status".into()),
            selector: OperationSelector {
                transport: Transport::HTTP,
                method: "GET".into(),
                normalized_path: "/session/status".into(),
            },
            transport: Transport::HTTP,
            request_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1status/get/parameters".into(),
                digest: "sha256:d23826e2e1c7b471eaa7b8d3544d572be3465ef98fe266ad3d0a362c99915834".into(),
            },
            success_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1status/get/responses/200".into(),
                digest: "sha256:6e5bb7fdaf7fa0d64e9b9604ab8cd069273d9966ce32ff854900f0b8da7e3643".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![],
            source: SourceRef {
                path: "packages/sdk/openapi.json".into(),
                lines: (5512, 5573),
                sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec![],
            unsupported_fields: vec!["directory".into(), "workspace".into()],
        },
        InventoryEntry {
            inventory_id: "session.abort".into(),
            upstream_operation_id: Some("session.abort".into()),
            selector: OperationSelector {
                transport: Transport::HTTP,
                method: "POST".into(),
                normalized_path: "/session/:sessionID/abort".into(),
            },
            transport: Transport::HTTP,
            request_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1abort/post/parameters".into(),
                digest: "sha256:55d74a6c54942645c87f066bbc8ece2f40062ef7f27ac52a831460b115ba9f26".into(),
            },
            success_schema_ref: SchemaRef {
                path: "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1abort/post/responses/200".into(),
                digest: "sha256:31ad44d7b836e078cb9ac260f38b17a53f0b53ac99652b6b34b2d0e1aefc58f5".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "packages/sdk/openapi.json".into(),
                lines: (6660, 6727),
                sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec!["sessionID".into()],
            unsupported_fields: vec!["directory".into(), "workspace".into()],
        },
    ]
});

pub fn classify(selector: &OperationSelector) -> Option<&'static InventoryEntry> {
    INVENTORY.iter().find(|e| &e.selector == selector)
}
