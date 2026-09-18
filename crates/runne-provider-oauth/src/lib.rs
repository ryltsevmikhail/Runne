#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

//! Pure bounded OAuth credential and request descriptor primitives.

mod credential;
mod pkce;
mod provider;
mod stored;

pub use credential::*;
pub use pkce::*;
pub use provider::*;
pub use stored::{encode_stored_envelope, parse_stored_envelope, parse_unversioned_import};
