//! ReplayStore — SQLite-backed replay subscription persistence.
//!
//! Implements [`runne_application::ports::ReplayStorePort`] using
//! the `_replay_subscriptions` table and the `events` table.
//!
//! All SQL operations are dispatched through [`tokio::task::spawn_blocking`]
//! to avoid blocking the async runtime.

include!("replay_store/prelude.rs");
include!("replay_store/inventory.rs");
include!("replay_store/events.rs");
include!("replay_store/sessions.rs");
include!("replay_store/store.rs");
include!("replay_store/open_baseline.rs");
include!("replay_store/open_gap_baseline_v2.rs");
include!("replay_store/open_baseline_v2.rs");
include!("replay_store/resume_tx_v2.rs");
#[cfg(test)]
include!("replay_store/open_baseline_v2_tests.rs");
#[cfg(test)]
include!("replay_store/open_baseline_v2_lifecycle_tests.rs");
#[cfg(test)]
include!("replay_store/open_baseline_v2_guard_tests.rs");
include!("replay_store/open_session.rs");
include!("replay_store/retention.rs");
include!("replay_store/read_page.rs");
include!("replay_store/acknowledge.rs");
include!("replay_store/complete_catch_up.rs");
include!("replay_store/continue_live.rs");
include!("replay_store/poll_live.rs");
include!("replay_store/close_session.rs");

include!("replay_store/trait_impl.rs");

include!("replay_store/public.rs");
include!("replay_store/tests.rs");
