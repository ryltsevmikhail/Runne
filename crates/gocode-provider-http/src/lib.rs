#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Profile-bound HTTP provider adapter with no ambient transport behavior.

mod adapter;
mod profile;
mod transport;

pub use adapter::HttpProviderAdapter;
pub use profile::{ProfileError, ProviderAdapterProfile};
pub use transport::{
    HttpTransport, HttpTransportRequest, HttpTransportResponse, SecretMaterializer, TransportError,
};
