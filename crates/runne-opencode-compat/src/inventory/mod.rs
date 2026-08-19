//! Inventory entry — full route metadata. Std-only, zero deps.

mod entries;

pub use entries::INVENTORY;

use crate::classify::{CompatibilityClass, Confidence, ImplementationStatus, RejectionRationale};
use crate::profile::OperationSelector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    pub inventory_id: String,
    pub upstream_operation_id: Option<String>,
    pub selector: OperationSelector,
    pub transport: crate::profile::Transport,
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

pub fn classify(selector: &OperationSelector) -> Option<&'static InventoryEntry> {
    INVENTORY.iter().find(|e| &e.selector == selector)
}
