//! Offline owner-only settlement for uncertain provider dispatches.
//!
//! Runs only against a stopped installation: the bootstrap locks prove that no
//! runtime owns the database. The command never starts a service and never
//! contacts a provider; it closes dispatch attempts that provably never started
//! a delivery, so a stuck effect window cannot block a safe exit, the idle gate
//! or a protected image upgrade.

use runne_daemon::bootstrap::bootstrap;
use runne_daemon::config::load_external_config;
use runne_provider::ProviderPreEffectRejection;
use runne_store::provider::{ProviderStoreError, SqliteProviderDispatchStore};
use std::time::{SystemTime, UNIX_EPOCH};

const CANDIDATE_LIMIT: usize = 64;

/// Runs one offline settlement pass and prints a closed JSON summary.
///
/// # Errors
///
/// Returns an error when the installation config, the exclusive database
/// locks, the settlement store or its proof fail.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_external_config()?;
    let bootstrap = bootstrap(&config)?;
    if !bootstrap.db_existed {
        return Err("settlement requires an existing runtime installation".into());
    }
    let locks = bootstrap.locks;
    let store =
        SqliteProviderDispatchStore::open_with_connection(&config.db_path, bootstrap.db_conn)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock unavailable")?
        .as_secs();
    let candidates = store.uncertain_without_delivery_candidates(CANDIDATE_LIMIT, now)?;
    let mut settled = 0usize;
    let mut unproven = 0usize;
    for attempt in &candidates {
        match store.settle_uncertain_without_delivery(
            *attempt,
            ProviderPreEffectRejection::AdapterRejected,
            now,
        ) {
            Ok(_) => settled = settled.saturating_add(1),
            Err(ProviderStoreError::RecoveryConflict) => unproven = unproven.saturating_add(1),
            Err(error) => return Err(Box::new(error)),
        }
    }
    drop(store);
    drop(locks);
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "candidates": candidates.len(),
            "settled": settled,
            "unproven": unproven,
        })
    );
    Ok(())
}
