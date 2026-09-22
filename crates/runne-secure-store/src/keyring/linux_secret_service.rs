//! Linux Secret Service facade for the persistent half of the combo store.
//!
//! Scope (DESIGN v6 §6, facade items F1′/F2/F5): unique-name-bound owner
//! validation, DH-encrypted session, unlocked-only fail-closed reads with no
//! prompt/unlock surface by construction, and keyring-3.6.3-compatible item
//! layout. The production libdbus transport lives in [`libdbus`]; the combo
//! store in [`combo`] pairs it with the keyutils cache half; tests bind the
//! same logic over injected fakes without touching a real session bus,
//! keyring, or credential store.

pub(super) use cache::{CacheError, KeyutilsCache};
pub(super) use combo::{ComboError, SsVerifiedWrite};
pub(super) use facade::SsFacadeError;
pub(super) use owner::ProcessFacts;
pub(super) use port::{SecretServiceBus, SsBusError};
mod cache;
mod combo;
mod dh_session;
mod facade;
mod item_layout;
mod libdbus;
mod owner;
mod port;

pub(super) use cache::KernelKeyutilsCache;
pub(super) use combo::{LinuxComboPersistentStore, provider_identity, version_identity};
pub(super) use item_layout::EntryIdentity;
pub(super) use libdbus::{LibdbusSecretServiceBus, derived_session_bus_address};
pub(super) use owner::ProcProcessFacts;

#[cfg(test)]
mod tests;
