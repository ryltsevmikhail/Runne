#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![allow(rustdoc::broken_intra_doc_links)]

//! `gocode-store` — SQLite persistence adapter for GOCODE Runtime.
//!
//! ## Architecture
//!
//! * **Schema** — DDL, migrations, startup PRAGMA gates ([`schema`])
//! * **Codec** — durable encoding/decoding for event payloads and receipts ([`codec`])
//! * **Integrity** — SHA-256 integrity digest computation ([`integrity`])
//! * **Store** — `StoreTransaction`, EventStore/UnitOfWork/IdGenerator/Clock impl ([`store`])

pub mod atomic_pre_effect;
pub mod codec;
pub mod integrity;
pub mod migration_codec;
pub mod migration_store;
pub mod provider;
pub mod replay_store;
pub mod schema;
pub mod store;
pub mod verification;
