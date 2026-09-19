#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! `runne-application` — application-layer orchestration for Runne Runtime.
//!
//! ## Architecture
//!
//! * **Ports** — abstract traits for persistence, identity, time ([`ports`])
//! * **Errors** — closed, typed application errors ([`errors`])
//! * **Fingerprint** — SHA-256 command identity for idempotency ([`fingerprint`])
//! * **Pipeline** — internal execution engine, not public API (`pipeline`)
//! * **Commands** — input/output DTO for use cases ([`commands`])
//! * **Service** — public crate::service::TaskRunService facade ([`service`])

pub mod command_reconciliation;
pub mod commands;
pub mod conversation_service;
pub mod conversation_text_service;
pub mod errors;
pub mod fingerprint;
pub mod local_session;
pub mod migration;
pub(crate) mod pipeline;
mod pipeline_submit;
pub mod ports;
pub mod prohibited_content;
pub mod project_trust;
pub mod project_workspace_service;
pub mod provider;
pub mod replay_service;
pub mod security;
pub mod service;
pub mod verification;
