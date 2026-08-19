#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::unnecessary_cast)]

//! `runne-plugin-protocol` — wire primitives, deterministic CBOR,
//! bootstrap handshake, frame codec, session envelope.
//!
//! No external dependencies. Protocol crate is independent of
//! `runne-domain` — wire identifiers use their own newtypes.
//!
//! ## Architecture
//!
//! * **IDs / Version** — wire UUIDv7 newtypes, bounded strings, ProtocolVersion ([`id`])
//! * **Digests** — role-separated digest newtypes, Sha256Provider trait ([`digest`])
//! * **CBOR** — deterministic CBOR codec (RFC 8949 subset) ([`cbor`])
//! * **Frame** — uint32_be length prefix + CBOR payload codec ([`frame`])
//! * **Bootstrap** — 5 handshake message types ([`bootstrap`])
//! * **Session** — post-handshake message envelope ([`session`])
//! * **Profile** — support profiles, limits, validation errors ([`profile`])

pub mod bootstrap;
pub mod bootstrap_v2;
pub mod cbor;
pub mod digest;
pub mod frame;
pub mod id;
pub mod profile;
pub mod session;
