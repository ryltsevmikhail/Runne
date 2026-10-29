use super::super::BootstrapOutcome;
use crate::error::DaemonError;
use rand::{RngCore, rngs::OsRng};
use runne_store::schema;
use rusqlite::OptionalExtension as _;
use rustix::fs::{self, RenameFlags};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

mod io;
#[cfg(not(test))]
use io::Fault;
#[cfg(test)]
pub(crate) use io::Fault;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use io::set_fault;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use io::test_guard;
use io::{AnchorDir, checked_file, hook};

const FILE: &str = "native-enrollment-installation-v1.state";
const MARKER: &str = "native_enrollment_installation_v1";
const TAG: [u8; 4] = *b"NEI1";
const LENGTH: usize = 84;
const DOMAIN: &[u8] = b"runne/native-enrollment-installation/v1\0";

pub(crate) struct VerifiedNativeEnrollmentInstallation([u8; 32]);
impl VerifiedNativeEnrollmentInstallation {
    pub(crate) const fn installation_identity_digest(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn load_read_only(
    outcome: &BootstrapOutcome,
) -> Result<VerifiedNativeEnrollmentInstallation, DaemonError> {
    load_or_provision(outcome, false)
}

pub(crate) fn provision_after_provider_bound_v2(
    outcome: &BootstrapOutcome,
) -> Result<VerifiedNativeEnrollmentInstallation, DaemonError> {
    load_or_provision(outcome, true)
}

fn load_or_provision(
    outcome: &BootstrapOutcome,
    may_provision: bool,
) -> Result<VerifiedNativeEnrollmentInstallation, DaemonError> {
    let parent = AnchorDir::from_bootstrap(outcome)?;
    hook(Fault::Parent, &parent, FILE)?;
    let marker = read_marker(outcome)?;
    match read_exact(&parent, FILE, outcome) {
        Ok(record) => finish_existing(&parent, outcome, marker, record, may_provision),
        Err(_) if parent.exists(FILE) || marker.is_some() || !may_provision => Err(error()),
        Err(_) => provision(&parent, outcome),
    }
}

fn finish_existing(
    parent: &AnchorDir,
    outcome: &BootstrapOutcome,
    marker: Option<[u8; 32]>,
    record: [u8; LENGTH],
    may_provision: bool,
) -> Result<VerifiedNativeEnrollmentInstallation, DaemonError> {
    let digest = digest(&record);
    match marker {
        Some(value) if value == digest => {
            parent.verify_current()?;
            Ok(VerifiedNativeEnrollmentInstallation(digest))
        }
        Some(_) | None if !may_provision => Err(error()),
        Some(_) => Err(error()),
        None => {
            parent.verify_current()?;
            write_marker(outcome, &digest)?;
            parent.verify_current()?;
            Ok(VerifiedNativeEnrollmentInstallation(digest))
        }
    }
}

fn provision(
    parent: &AnchorDir,
    outcome: &BootstrapOutcome,
) -> Result<VerifiedNativeEnrollmentInstallation, DaemonError> {
    let record = record_for(outcome)?;
    let temporary = format!("{FILE}.tmp-{}", uuid::Uuid::now_v7());
    let mut file = parent.create(&temporary)?;
    file.write_all(&record)
        .and_then(|()| file.sync_all())
        .map_err(|_| error())?;
    let identity = checked_file(&file)?;
    hook(Fault::Temp, parent, &temporary)?;
    if parent.stat(&temporary)? != identity {
        return Err(error());
    }
    fs::renameat_with(
        parent.fd(),
        &temporary,
        parent.fd(),
        FILE,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| error())?;
    fs::fsync(parent.fd()).map_err(|_| error())?;
    hook(Fault::Final, parent, FILE)?;
    let final_record = read_exact(parent, FILE, outcome)?;
    if final_record != record || parent.stat(FILE)? != identity {
        return Err(error());
    }
    hook(Fault::BeforeMarker, parent, FILE)?;
    parent.verify_current()?;
    let digest = digest(&record);
    write_marker(outcome, &digest)?;
    parent.verify_current()?;
    Ok(VerifiedNativeEnrollmentInstallation(digest))
}

fn record_for(outcome: &BootstrapOutcome) -> Result<[u8; LENGTH], DaemonError> {
    let lineage = schema::read_event_log_lineage_id(&outcome.db_conn)
        .map_err(|_| error())?
        .ok_or_else(error)?;
    let mut record = [0; LENGTH];
    record[..4].copy_from_slice(&TAG);
    while record[4..36].iter().all(|byte| *byte == 0) {
        OsRng.fill_bytes(&mut record[4..36]);
    }
    record[36..52].copy_from_slice(&outcome.authority_id);
    record[52..68].copy_from_slice(lineage.as_bytes());
    record[68..].copy_from_slice(&outcome.local_session_authority_id);
    Ok(record)
}

fn read_exact(
    parent: &AnchorDir,
    name: &str,
    outcome: &BootstrapOutcome,
) -> Result<[u8; LENGTH], DaemonError> {
    let mut file = parent.open_file(name)?;
    let identity = checked_file(&file)?;
    let mut record = [0; LENGTH];
    file.read_exact(&mut record).map_err(|_| error())?;
    if file.read(&mut [0]).map_err(|_| error())? != 0
        || checked_file(&file)? != identity
        || parent.stat(name)? != identity
        || !valid_record(&record, outcome)?
    {
        return Err(error());
    }
    Ok(record)
}

fn valid_record(record: &[u8; LENGTH], outcome: &BootstrapOutcome) -> Result<bool, DaemonError> {
    let lineage = schema::read_event_log_lineage_id(&outcome.db_conn)
        .map_err(|_| error())?
        .ok_or_else(error)?;
    Ok(record[..4] == TAG
        && record[4..36].iter().any(|byte| *byte != 0)
        && record[36..52] == outcome.authority_id
        && record[52..68] == *lineage.as_bytes()
        && record[68..] == outcome.local_session_authority_id)
}

fn read_marker(outcome: &BootstrapOutcome) -> Result<Option<[u8; 32]>, DaemonError> {
    outcome
        .db_conn
        .query_row(
            "SELECT value FROM _daemon_info WHERE key = ?1",
            [MARKER],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| error())?
        .map(|value| decode(&value))
        .transpose()
}

fn write_marker(outcome: &BootstrapOutcome, digest: &[u8; 32]) -> Result<(), DaemonError> {
    outcome
        .db_conn
        .execute(
            "INSERT INTO _daemon_info (key, value) VALUES (?1, ?2)",
            (MARKER, hex::encode(digest)),
        )
        .map_err(|_| error())
        .and_then(|count| if count == 1 { Ok(()) } else { Err(error()) })
}

fn decode(value: &str) -> Result<[u8; 32], DaemonError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(error());
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(value, &mut digest).map_err(|_| error())?;
    Ok(digest)
}

fn digest(record: &[u8; LENGTH]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(record);
    hasher.finalize().into()
}

fn error() -> DaemonError {
    DaemonError::Bootstrap("native enrollment installation anchor unavailable".into())
}
