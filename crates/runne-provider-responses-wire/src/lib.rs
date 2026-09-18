#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_lines
)]

//! Bounded text-only OpenAI Responses wire profiles for fixed providers.

mod configured;
mod pricing;
mod profile;
mod profile_binding;
mod profile_components;
mod profile_validation_methods;
mod render;
mod stream;

pub use configured::*;
pub use profile::*;
pub use profile_components::ProfileError;
pub use render::*;
pub use stream::*;
