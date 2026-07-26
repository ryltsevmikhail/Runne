#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]

//! gocode-store — SQLite persistence for gocode-runtime.
//!
//! Implements EventStore, UnitOfWork from gocode-application.
//! Embedded SQLite via rusqlite with bundled SQLite.
