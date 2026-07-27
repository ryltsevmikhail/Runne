#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! `gocode-application` — application-layer orchestration for GOCODE Runtime.
//!
//! ## Architecture
//!
//! * **Ports** — abstract traits for persistence, identity, time ([`ports`])
//! * **Errors** — closed, typed application errors ([`errors`])
//! * **Fingerprint** — SHA-256 command identity for idempotency ([`fingerprint`])
//! * **Pipeline** — internal execution engine, not public API (`pipeline`)
//! * **Commands** — input/output DTO for use cases ([`commands`])
//! * **Service** — public crate::service::TaskRunService facade ([`service`])

pub mod commands;
pub mod conversation_service;
pub mod errors;
pub mod fingerprint;
pub mod migration;
pub(crate) mod pipeline;
pub mod ports;
pub mod service;
pub mod verification;
