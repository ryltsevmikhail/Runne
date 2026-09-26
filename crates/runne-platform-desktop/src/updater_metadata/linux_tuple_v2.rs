//! Linux staged `AppDir` tuple V2 production.
use super::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleError, NativeEnrollmentTupleV2,
    UpdateTargetV2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxTupleV2Output {
    schema_version: u32,
    target: UpdateTargetV2,
    tuple: NativeEnrollmentTupleV2,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationReceiptV1 {
    schema_version: u32,
    artifact_sha256: String,
    source_commit: String,
    release_candidate_sha256: String,
    desktop_sha256: String,
    cli_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
    checks: [String; 2],
    check_commands: [String; 2],
    check_exit_statuses: [i32; 2],
    check_log_sha256: String,
    qualified_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl QualificationReceiptV1 {
    fn verify(
        &self,
        target: &UpdateTargetV2,
        artifact: &str,
        components: &[String],
        qualified_at: u64,
        expires_at: u64,
    ) -> bool {
        self.schema_version == 1
            && self.artifact_sha256 == artifact
            && self.source_commit.len() == 40
            && self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && hex::encode(Sha256::digest(self.source_commit.as_bytes()))
                == self.release_candidate_sha256
            && self.release_candidate_sha256 == target.release_candidate_sha256
            && self.desktop_sha256 == components[0]
            && self.cli_sha256 == components[1]
            && self.daemon_sha256 == components[2]
            && self.contract_sha256 == components[3]
            && self.checks[0] == "desktop-library-tests"
            && self.checks[1] == "appimage-component-match"
            && self.check_commands[0] == "cargo test -p runne-platform-desktop --lib"
            && self.check_commands[1] == "AppImage extraction and required-component cmp checks"
            && self.check_exit_statuses == [0, 0]
            && self.check_log_sha256.len() == 64
            && self
                .check_log_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && self.qualified_at_unix_seconds == qualified_at
            && self.expires_at_unix_seconds == expires_at
    }
}

/// Measures Tauri's canonical `Runne.AppDir`, final `AppImage`, and qualification receipt.
/// Digest-bearing target fields are always derived from opened files.
#[allow(clippy::too_many_arguments)]
pub fn produce_linux_native_enrollment_tuple_v2(
    app_dir: &Path,
    appimage: &Path,
    receipt: &Path,
    output: &Path,
    mut target: UpdateTargetV2,
    qualified_at: u64,
    qualification_expires: u64,
) -> Result<LinuxTupleV2Output, NativeEnrollmentTupleError> {
    if target.platform != "linux" {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let app_dir = app_dir.canonicalize().map_err(reject)?;
    let root = File::open(&app_dir).map_err(reject)?;
    let rels = [
        "usr/bin/runne-desktop",
        "usr/bin/runne",
        "usr/bin/runned",
        "usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json",
    ];
    let files = rels
        .map(|rel| open_beneath(&root, Path::new(rel)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let before = files
        .iter()
        .map(fingerprint)
        .collect::<Result<Vec<_>, _>>()?;
    let digests = files.iter().map(hash_file).collect::<Result<Vec<_>, _>>()?;
    let (artifact_sha, artifact_size, artifact, artifact_before) = measure_path(appimage)?;
    let (receipt_sha, _, receipt_file, receipt_before) = measure_path(receipt)?;
    let receipt_bytes = read_file(&receipt_file)?;
    if hex::encode(Sha256::digest(&receipt_bytes)) != receipt_sha {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let receipt_value: QualificationReceiptV1 =
        serde_json::from_slice(&receipt_bytes).map_err(reject)?;
    let log_path = receipt.with_extension("log");
    let (log_sha, _, log_file, log_before) = measure_path(&log_path)?;
    if !receipt_value.verify(
        &target,
        &artifact_sha,
        &digests,
        qualified_at,
        qualification_expires,
    ) || receipt_value.check_log_sha256 != log_sha
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    target.artifact_sha256.clone_from(&artifact_sha);
    target.artifact_size = artifact_size;
    target.bundle_sha256.clone_from(&digests[3]);
    target.runtime_digest.clone_from(&digests[2]);
    let tuple = NativeEnrollmentTupleV2::new(
        target.release_candidate_sha256.clone(),
        digests[0].clone(),
        digests[1].clone(),
        digests[2].clone(),
        digests[3].clone(),
        &target,
    )?;
    let row = NativeEnrollmentQualificationRowV1::new(
        &target,
        &tuple,
        receipt_sha,
        qualified_at,
        qualification_expires,
    )?;
    let tuple = tuple.with_qualification(&target, row)?;
    for ((file, rel), expected) in files.iter().zip(rels).zip(before) {
        if fingerprint(file)? != expected
            || fingerprint(&open_beneath(&root, Path::new(rel))?)? != expected
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
    }
    if fingerprint(&artifact)? != artifact_before
        || fingerprint(&receipt_file)? != receipt_before
        || fingerprint(&log_file)? != log_before
        || fingerprint(&open_nofollow(appimage)?)? != artifact_before
        || fingerprint(&open_nofollow(receipt)?)? != receipt_before
        || fingerprint(&open_nofollow(&log_path)?)? != log_before
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let result = LinuxTupleV2Output {
        schema_version: 1,
        target,
        tuple,
    };
    let bytes = serde_json::to_vec(&result).map_err(reject)?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(reject)?;
    out.write_all(&bytes).map_err(reject)?;
    out.sync_all().map_err(reject)?;
    Ok(result)
}

fn open_beneath(root: &File, relative: &Path) -> Result<File, NativeEnrollmentTupleError> {
    let components = relative.components().collect::<Vec<_>>();
    let mut dir = root.try_clone().map_err(reject)?;
    for component in &components[..components.len() - 1] {
        let std::path::Component::Normal(name) = component else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        dir = File::from(
            rustix::fs::openat(
                &dir,
                *name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(reject)?,
        );
    }
    let std::path::Component::Normal(name) = components
        .last()
        .ok_or(NativeEnrollmentTupleError::Rejected)?
    else {
        return Err(NativeEnrollmentTupleError::Rejected);
    };
    let file = File::from(
        rustix::fs::openat(
            &dir,
            *name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(reject)?,
    );
    if !file.metadata().map_err(reject)?.is_file() {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(file)
}

fn measure_path(
    path: &Path,
) -> Result<(String, u64, File, Fingerprint), NativeEnrollmentTupleError> {
    let file = open_nofollow(path)?;
    if !file.metadata().map_err(reject)?.is_file() {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let size = file.metadata().map_err(reject)?.len();
    let stamp = fingerprint(&file)?;
    Ok((hash_file(&file)?, size, file, stamp))
}

fn open_nofollow(path: &Path) -> Result<File, NativeEnrollmentTupleError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(reject)
}

#[derive(PartialEq)]
struct Fingerprint(u64, u64, u64, i64, i64);
fn fingerprint(file: &File) -> Result<Fingerprint, NativeEnrollmentTupleError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(reject)?;
    if !m.is_file() {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(Fingerprint(
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
    ))
}
fn hash_file(file: &File) -> Result<String, NativeEnrollmentTupleError> {
    let mut reader = file.try_clone().map_err(reject)?;
    reader.rewind().map_err(reject)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(reject)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
fn read_file(file: &File) -> Result<Vec<u8>, NativeEnrollmentTupleError> {
    let mut reader = file.try_clone().map_err(reject)?;
    reader.rewind().map_err(reject)?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(reject)?;
    Ok(bytes)
}
fn reject(_: impl std::fmt::Display) -> NativeEnrollmentTupleError {
    NativeEnrollmentTupleError::Rejected
}

#[cfg(test)]
#[path = "linux_tuple_v2_tests.rs"]
mod tests;
