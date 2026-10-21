//! Dormant confidential configured metadata; no public composition or authority.
mod bounded_capture;
mod capture;
mod digest;
mod error;
mod identity;
mod json_envelope;
mod map_only;
mod owner;
mod owner_state;
mod record;
mod storage;
mod storage_header;
mod storage_record;

use error::MetadataQueryError;
use identity::*;
use owner::*;
use record::*;

#[cfg(test)]
mod tests;
