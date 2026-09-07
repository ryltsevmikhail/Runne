//! Security-critical broker primitives for artifact handling. This crate
//! owns no business logic: it opens pinned content addresses no-follow,
//! enforces one-time descriptors and the grant state machine, and
//! provides audited SCM_RIGHTS fd transport on unix.

pub mod broker;

pub use broker::error::BrokerError;
