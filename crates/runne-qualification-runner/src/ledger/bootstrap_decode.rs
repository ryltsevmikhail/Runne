use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::RunBinding;

use crate::{BootstrapArmed, BootstrapPreparation, QualificationReplayLedgerError};

pub(super) type StoredArmed = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    u64,
    u64,
    u64,
    u64,
    Vec<u8>,
);

pub(super) fn stored_armed(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredArmed> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
    ))
}

pub(super) fn armed_from_stored(
    value: StoredArmed,
) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
    let (
        offer,
        context,
        nonce,
        source,
        run,
        namespace,
        candidate,
        raw,
        manifest,
        profile,
        issued,
        expires,
        run_not_after,
        max_duration,
        challenge,
    ) = value;
    let binding = RunBinding::new(
        &run,
        array(source)?,
        array(candidate)?,
        array(raw)?,
        array(namespace)?,
        array(manifest)?,
        array(profile)?,
    )
    .map_err(|_| QualificationReplayLedgerError)?;
    let preparation = BootstrapPreparation::new(
        binding,
        array(offer)?,
        array(context)?,
        array(nonce)?,
        issued,
        expires,
        run_not_after,
        max_duration,
    )?;
    BootstrapArmed::new(preparation, array(challenge)?)
}

pub(super) const fn is_current(preparation: &BootstrapPreparation, now: u64) -> bool {
    now >= preparation.issued_at()
        && now < preparation.expires_at()
        && now < preparation.run_not_after()
}

pub(super) const fn is_current_armed(armed: &BootstrapArmed, now: u64) -> bool {
    now >= armed.issued_at() && now < armed.expires_at() && now < armed.run_not_after()
}

pub(super) fn system_now() -> Result<u64, QualificationReplayLedgerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| QualificationReplayLedgerError)
}

fn array<const N: usize>(value: Vec<u8>) -> Result<[u8; N], QualificationReplayLedgerError> {
    value.try_into().map_err(|_| QualificationReplayLedgerError)
}
