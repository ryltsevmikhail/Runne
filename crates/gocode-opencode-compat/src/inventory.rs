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
                sha: "66495a2a".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingConversationAggregate),
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
                path: "".into(),
                digest: "".into(),
            },
            success_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "session.ts".into(),
                lines: (0, 0),
                sha: "66495a2a".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingPromptExecution),
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
                path: "".into(),
                digest: "".into(),
            },
            success_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "session.ts".into(),
                lines: (0, 0),
                sha: "66495a2a".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingPromptExecution),
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
                path: "".into(),
                digest: "".into(),
            },
            success_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![],
            source: SourceRef {
                path: "session.ts".into(),
                lines: (0, 0),
                sha: "66495a2a".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingReadModel),
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
                path: "".into(),
                digest: "".into(),
            },
            success_schema_ref: SchemaRef {
                path: "".into(),
                digest: "".into(),
            },
            error_schema_refs: vec![],
            stream_semantics: None,
            auth_scope: AuthScope::Session,
            side_effects: vec![SideEffect::MutatesState],
            source: SourceRef {
                path: "session.ts".into(),
                lines: (0, 0),
                sha: "66495a2a".into(),
                observed_date: "2026-07-24".into(),
            },
            confidence: Confidence::Observed,
            classification: CompatibilityClass::Unsupported,
            implementation_status: ImplementationStatus::Planned,
            rationale: Some(RejectionRationale::MissingCancelUseCase),
        },
    ]
});

pub fn classify(selector: &OperationSelector) -> Option<&'static InventoryEntry> {
    INVENTORY.iter().find(|e| &e.selector == selector)
}
