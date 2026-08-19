use std::sync::LazyLock;

use crate::classify::{CompatibilityClass, Confidence, ImplementationStatus, RejectionRationale};
use crate::inventory::{
    AuthScope, InventoryEntry, SchemaRef, SideEffect, SourceRef, StreamSemantics,
};
use crate::profile::{OperationSelector, Transport};

const BASELINE_SHA: &str = "66495a2a22cd0a57efcc4f721e65532f0987b4e8";
const PLACEHOLDER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn schema_ref(path: &str, digest: &str) -> SchemaRef {
    SchemaRef {
        path: path.into(),
        digest: digest.into(),
    }
}

fn empty_schema() -> SchemaRef {
    schema_ref("", "")
}

fn source_ref(path: &str, lines: (u32, u32)) -> SourceRef {
    SourceRef {
        path: path.into(),
        lines,
        sha: BASELINE_SHA.into(),
        observed_date: "2026-07-24".into(),
    }
}

fn selector(method: &str, path: &str) -> OperationSelector {
    OperationSelector {
        transport: Transport::HTTP,
        method: method.into(),
        normalized_path: path.into(),
    }
}

pub static INVENTORY: LazyLock<Vec<InventoryEntry>> = LazyLock::new(|| {
    vec![
        InventoryEntry {
            inventory_id: "session.create".into(),
            upstream_operation_id: Some("session.create".into()),
            selector: selector("POST", "/session"),
            transport: Transport::HTTP,
            request_schema_ref: empty_schema(),
            success_schema_ref: empty_schema(),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::System,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("session.ts", (0, 0)),
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
            selector: selector("POST", "/session/:sessionID/message"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1message/post/requestBody",
                "sha256:9660f4c18156783f481a9743370462fb9ac7b68edc3f11a8441ea7002e1252f3",
            ),
            success_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1message/post/responses/200",
                "sha256:dadd1246f1d693236181c9fdb6ada30a215cd3b17f9b545f254e893d5f2358ea",
            ),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("packages/sdk/openapi.json", (6202, 6359)),
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
            selector: selector("POST", "/session/:sessionID/prompt_async"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1prompt_async/post/requestBody",
                "sha256:9660f4c18156783f481a9743370462fb9ac7b68edc3f11a8441ea7002e1252f3",
            ),
            success_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1prompt_async/post/responses/204",
                "sha256:e97df8825be7e45d6bcb9e015d4372919d158ab5661e9941c9ab99f9b3775aa4",
            ),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("packages/sdk/openapi.json", (7102, 7241)),
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
            selector: selector("GET", "/session/status"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1status/get/parameters",
                "sha256:d23826e2e1c7b471eaa7b8d3544d572be3465ef98fe266ad3d0a362c99915834",
            ),
            success_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1status/get/responses/200",
                "sha256:6e5bb7fdaf7fa0d64e9b9604ab8cd069273d9966ce32ff854900f0b8da7e3643",
            ),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![],
            source: source_ref("packages/sdk/openapi.json", (5512, 5573)),
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
            selector: selector("POST", "/session/:sessionID/abort"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1abort/post/parameters",
                "sha256:55d74a6c54942645c87f066bbc8ece2f40062ef7f27ac52a831460b115ba9f26",
            ),
            success_schema_ref: schema_ref(
                "packages/sdk/openapi.json#/paths/~1session~1{sessionID}~1abort/post/responses/200",
                "sha256:31ad44d7b836e078cb9ac260f38b17a53f0b53ac99652b6b34b2d0e1aefc58f5",
            ),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("packages/sdk/openapi.json", (6660, 6727)),
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Semantic,
            implementation_status: ImplementationStatus::Verified,
            rationale: None,
            supported_fields: vec!["sessionID".into()],
            unsupported_fields: vec!["directory".into(), "workspace".into()],
        },
        // Phase 8: event/permission mappings beyond text-only session profile.
        // These entries are classified as unsupported in v1 but explicitly
        // inventoried so the adapter remains fail-closed and future profile
        // revisions can promote them to planned/implemented.
        InventoryEntry {
            inventory_id: "event.stream".into(),
            upstream_operation_id: Some("event.stream".into()),
            selector: selector("GET", "/session/:sessionID/events"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref("packages/schema/src/session-event.ts", PLACEHOLDER),
            success_schema_ref: schema_ref("packages/schema/src/session-event.ts", PLACEHOLDER),
            error_schema_refs: vec![],
            stream_semantics: Some(StreamSemantics {
                stream_type: "SSE".into(),
                event_types: vec![
                    "session.created".into(),
                    "session.message".into(),
                    "session.idle".into(),
                    "session.next.*".into(),
                ],
            }),
            auth_scope: AuthScope::Session,
            side_effects: vec![],
            source: source_ref("packages/schema/src/session-event.ts", (0, 0)),
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingReadModel),
            supported_fields: vec![],
            unsupported_fields: vec!["all event types".into()],
        },
        InventoryEntry {
            inventory_id: "permission.request".into(),
            upstream_operation_id: Some("permission.request".into()),
            selector: selector("POST", "/session/:sessionID/permission"),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref("packages/opencode/src/permission", PLACEHOLDER),
            success_schema_ref: schema_ref("packages/opencode/src/permission", PLACEHOLDER),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("packages/opencode/src/permission", (0, 0)),
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingCapabilityEngine),
            supported_fields: vec![],
            unsupported_fields: vec!["ruleset".into(), "question".into(), "approval".into()],
        },
        InventoryEntry {
            inventory_id: "permission.respond".into(),
            upstream_operation_id: Some("permission.respond".into()),
            selector: selector(
                "POST",
                "/session/:sessionID/permission/:permissionID/respond",
            ),
            transport: Transport::HTTP,
            request_schema_ref: schema_ref("packages/opencode/src/permission", PLACEHOLDER),
            success_schema_ref: schema_ref("packages/opencode/src/permission", PLACEHOLDER),
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: source_ref("packages/opencode/src/permission", (0, 0)),
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingCapabilityEngine),
            supported_fields: vec![],
            unsupported_fields: vec!["approved".into(), "denied".into(), "auto".into()],
        },
    ]
});
