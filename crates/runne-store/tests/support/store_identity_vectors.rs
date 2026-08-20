use std::fs;
use std::path::Path;

pub(crate) const SOURCE_COMMIT: &str = "556f09eb";
pub(crate) const INTENT_DIGEST: [u8; 32] = [
    172, 84, 182, 48, 254, 219, 99, 4, 249, 169, 88, 114, 118, 35, 102, 9, 175, 222, 104, 75, 140,
    122, 14, 40, 155, 86, 41, 106, 107, 42, 174, 9,
];
pub(crate) const GAP_DIGEST: [u8; 32] = [
    212, 30, 78, 183, 18, 162, 136, 150, 137, 38, 35, 127, 222, 229, 62, 121, 122, 6, 4, 41, 218,
    158, 7, 206, 197, 148, 229, 55, 125, 167, 10, 144,
];
pub(crate) const EVIDENCE_DIGEST: [u8; 32] = [
    88, 25, 80, 110, 120, 250, 189, 166, 227, 147, 54, 152, 157, 87, 179, 64, 141, 5, 78, 55, 10,
    42, 191, 85, 7, 67, 41, 156, 122, 112, 230, 251,
];

pub(crate) const IDENTITIES: &[(&str, &str)] = &[
    (
        "gocode-runtime/consumption-intent-reservation/v1\0",
        "runne-runtime/consumption-intent-reservation/v1\0",
    ),
    (
        "gocode-project-workspace-command\x01",
        "runne-project-workspace-command\x01",
    ),
    ("gocode-migration-scope\x01", "runne-migration-scope\x01"),
    (
        "gocode.store.aggregate-state-snapshot",
        "runne.store.aggregate-state-snapshot",
    ),
    (
        "gocode/replay-retention-manifest/v1\0",
        "runne/replay-retention-manifest/v1\0",
    ),
    (
        "gocode/replay-retention-baseline-resume-manifest/v2\0",
        "runne/replay-retention-baseline-resume-manifest/v2\0",
    ),
    (
        "gocode/replay-gap-range/v1\0",
        "runne/replay-gap-range/v1\0",
    ),
    (
        "gocode.provider-scanner-recovery",
        "runne.provider-scanner-recovery",
    ),
    (
        "GOCODE_CREDENTIAL_TOMBSTONE_V1\0",
        "RUNNE_CREDENTIAL_TOMBSTONE_V1\0",
    ),
    (
        "GOCODE_PROVIDER_EXECUTION_SEMANTIC_V1\0",
        "RUNNE_PROVIDER_EXECUTION_SEMANTIC_V1\0",
    ),
    ("gocode:evidence-content:v1", "runne:evidence-content:v1"),
    (
        "GOCODE_SYNTHETIC_VERIFICATION_BACKUP_V1\0",
        "RUNNE_SYNTHETIC_VERIFICATION_BACKUP_V1\0",
    ),
    ("GOCODE_STORED_EVENT_V1\0", "RUNNE_STORED_EVENT_V1\0"),
];

pub(crate) fn file_snapshot(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

pub(crate) fn sidecar_path(base: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.scanner-recovery", base.display()))
}
