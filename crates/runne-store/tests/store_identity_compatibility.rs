//! Independent sourcecraft@556f persistent-identity compatibility vectors.
//!
//! These vectors deliberately seed durable bytes directly. They do not obtain
//! expected values from the current store writer or from mutable goldens.

#[path = "support/store_identity_vectors.rs"]
mod vectors;

mod store_identity_compatibility_parts {
    mod durable_readers;
    mod fixed_vectors;
}
