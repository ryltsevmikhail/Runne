#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools
)]

//! Pure, credential-free Radius `pi-messages` wire and dynamic catalog.

mod catalog;
mod render;
mod stream;

pub use catalog::{
    DEFAULT_RADIUS_GATEWAY, RadiusAccounting, RadiusCatalog, RadiusCatalogModel, RadiusConfigError,
    RadiusCost, RadiusProfile,
};
pub use render::{RadiusRenderError, RadiusRenderer};
pub use stream::{RadiusStreamDecoder, RadiusStreamError};
