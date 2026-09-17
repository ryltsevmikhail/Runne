//! Safe, bounded consumption of the fixture writer stderr log.
//!
//! The raw log may contain arbitrary writer output (panics can format
//! secret material), so it is observed exactly once under a hard byte
//! bound. Overflow, unreadable or non-regular sinks fail closed: a
//! truncated log is never presented as a complete observation. The
//! summary keeps only lines that exactly match the audited fixed stage
//! vocabulary and reports everything else as an opaque suppressed-line
//! count; the raw bytes flow only through the harness secret scan before
//! the fixture root is deleted.

use std::io::Read as _;

/// Hard byte bound for one writer log observation; aligned with the
/// legacy service sink bound in `harness/legacy_sinks.rs`.
pub(super) const MAX_WRITER_LOG_BYTES: usize = 64 * 1024;

/// Upper bound on stage markers echoed into one summary so the failure
/// message itself stays bounded.
const MAX_REPORTED_STAGES: usize = 16;

const STAGE_LINES: &[&str] = &[
    "writer-stage=secret-inspect",
    "writer-stage=endpoint-receive",
    "writer-stage=session-observe",
    "writer-stage=authenticated-run",
    "writer-stage-failed=secret-inspect",
    "writer-stage-failed=endpoint-receive",
    "writer-stage-failed=session-observe",
    "writer-stage-failed=authenticated-run",
];

/// One bounded observation of the fixture writer stderr log.
pub(super) struct WriterLogObservation {
    /// Raw bounded bytes, for the harness secret scan only; never printed.
    pub(super) raw: Vec<u8>,
    /// The log exceeded the collection bound: `raw` holds only the first
    /// [`MAX_WRITER_LOG_BYTES`] bytes, so the scenario must fail closed
    /// instead of grounding a canary pass on a truncated log.
    pub(super) overflow: bool,
    /// Sanitized stage summary, safe to embed in failure messages.
    pub(super) summary: String,
}

/// Reads the fixture writer log exactly once under the byte bound. A
/// missing log is an empty observation (the writer never started);
/// anything unreadable or non-regular fails closed with a safe static
/// reason instead of a raw filesystem error.
pub(super) fn observe_writer_log(
    fixture_root: &std::path::Path,
) -> Result<WriterLogObservation, &'static str> {
    use std::os::unix::fs::MetadataExt as _;
    let log = fixture_root.join("writer-stderr.log");
    match std::fs::symlink_metadata(&log) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(WriterLogObservation {
            raw: Vec::new(),
            overflow: false,
            summary: sanitized_summary_from_bytes(&[]),
        }),
        Ok(metadata) if metadata.file_type().is_file() => {
            let file = std::fs::File::open(&log).map_err(|_| "writer stderr log is unreadable")?;
            let opened = file
                .metadata()
                .map_err(|_| "writer stderr log is unreadable")?;
            let same_file = opened.ino() == metadata.ino() && opened.dev() == metadata.dev();
            if !opened.is_file() || !same_file {
                return Err("writer stderr log is not a regular file");
            }
            let mut bytes = Vec::new();
            file.take(MAX_WRITER_LOG_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "writer stderr log is unreadable")?;
            let overflow = bytes.len() > MAX_WRITER_LOG_BYTES;
            bytes.truncate(MAX_WRITER_LOG_BYTES);
            let summary = sanitized_summary_from_bytes(&bytes);
            Ok(WriterLogObservation {
                raw: bytes,
                overflow,
                summary,
            })
        }
        Ok(_) => Err("writer stderr log is not a regular file"),
        Err(_) => Err("writer stderr log is unreadable"),
    }
}

/// Reduces raw log bytes to the safe summary: recognized stage markers in
/// order (capped at [`MAX_REPORTED_STAGES`], extras counted), plus the
/// opaque suppressed-line count. No raw writer output survives; invalid
/// UTF-8 degrades lossily without changing the byte-exact `raw` evidence.
fn sanitized_summary_from_bytes(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut stages: Vec<&str> = Vec::new();
    let mut omitted_stages = 0_usize;
    let mut suppressed = 0_usize;
    for line in text.lines() {
        if STAGE_LINES.contains(&line) {
            if stages.len() < MAX_REPORTED_STAGES {
                stages.push(line);
            } else {
                omitted_stages += 1;
            }
        } else {
            suppressed += 1;
        }
    }
    let reached = stages
        .iter()
        .map(|stage| stage.trim_start_matches("writer-stage"))
        .collect::<Vec<_>>()
        .join(" ");
    if omitted_stages == 0 {
        format!("writer-stages=[{reached}] suppressed-lines={suppressed}")
    } else {
        format!(
            "writer-stages=[{reached}] suppressed-lines={suppressed} \
             stages-omitted={omitted_stages}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_log(root: &std::path::Path, contents: &[u8]) {
        std::fs::write(root.join("writer-stderr.log"), contents).expect("log");
    }

    #[test]
    fn summary_keeps_only_the_fixed_stage_vocabulary() {
        let root = tempfile::tempdir().expect("fixture root");
        write_log(
            root.path(),
            b"writer-stage=secret-inspect\n\
              noise from the writer\n\
              writer-stage-failed=endpoint-receive\n\
              writer-stage=attacker-invented-stage\n\
              writer-stage=authenticated-run\n",
        );
        let observation = observe_writer_log(root.path()).expect("observation");
        assert_eq!(
            observation.summary,
            "writer-stages=[=secret-inspect -failed=endpoint-receive =authenticated-run] \
             suppressed-lines=2"
        );
        assert!(!observation.overflow);
    }

    #[test]
    fn summary_never_embeds_arbitrary_or_secret_content() {
        let root = tempfile::tempdir().expect("fixture root");
        let mut contents = format!("panic: cannot seal pair secret {SECRET}\n").into_bytes();
        contents.extend_from_slice(b"writer-stage=session-observe\nbacktrace with ");
        contents.extend_from_slice(SECRET.as_bytes());
        contents.push(b'\n');
        write_log(root.path(), &contents);
        let observation = observe_writer_log(root.path()).expect("observation");
        assert_eq!(observation.raw, contents);
        assert!(observation.summary.contains("=session-observe"));
        assert!(observation.summary.contains("suppressed-lines=2"));
        assert!(!observation.summary.contains(SECRET));
        assert!(!observation.summary.contains("panic"));
        assert!(!observation.summary.contains("backtrace"));
    }

    #[test]
    fn missing_log_reports_an_empty_summary() {
        let root = tempfile::tempdir().expect("fixture root");
        let observation = observe_writer_log(root.path()).expect("observation");
        assert_eq!(observation.summary, "writer-stages=[] suppressed-lines=0");
        assert!(observation.raw.is_empty());
        assert!(!observation.overflow);
    }

    #[test]
    fn log_at_the_exact_bound_is_a_complete_observation() {
        let root = tempfile::tempdir().expect("fixture root");
        write_log(root.path(), &vec![b'a'; MAX_WRITER_LOG_BYTES]);
        let observation = observe_writer_log(root.path()).expect("observation");
        assert!(!observation.overflow);
        assert_eq!(observation.raw.len(), MAX_WRITER_LOG_BYTES);
    }

    #[test]
    fn oversized_log_fails_closed_with_a_bounded_prefix() {
        let root = tempfile::tempdir().expect("fixture root");
        let mut contents = vec![b'a'; MAX_WRITER_LOG_BYTES];
        contents.extend_from_slice(b"writer-stage=authenticated-run\n");
        write_log(root.path(), &contents);
        let observation = observe_writer_log(root.path()).expect("observation");
        assert!(observation.overflow);
        assert_eq!(observation.raw.len(), MAX_WRITER_LOG_BYTES);
        // The stage marker beyond the bound must not enter the summary: a
        // truncated log never poses as a complete canary observation.
        assert!(!observation.summary.contains("authenticated-run"));
        assert!(observation.summary.contains("suppressed-lines="));
    }

    #[test]
    fn non_regular_log_fails_closed() {
        let directory = tempfile::tempdir().expect("fixture root");
        std::fs::create_dir(directory.path().join("writer-stderr.log")).expect("directory");
        assert!(matches!(
            observe_writer_log(directory.path()),
            Err("writer stderr log is not a regular file")
        ));
        let linked = tempfile::tempdir().expect("second fixture root");
        let target = linked.path().join("target.txt");
        std::fs::write(&target, b"legitimate").expect("target");
        std::os::unix::fs::symlink(&target, linked.path().join("writer-stderr.log"))
            .expect("symlink");
        assert!(matches!(
            observe_writer_log(linked.path()),
            Err("writer stderr log is not a regular file")
        ));
    }

    #[test]
    fn raw_bytes_stay_byte_exact_for_the_canary_scan() {
        let root = tempfile::tempdir().expect("fixture root");
        let mut contents = b"writer-stage=session-observe\n".to_vec();
        contents.extend_from_slice(b"panic with \xff\xfe raw bytes\n");
        write_log(root.path(), &contents);
        let observation = observe_writer_log(root.path()).expect("observation");
        assert_eq!(observation.raw, contents);
        assert_eq!(
            observation.summary,
            "writer-stages=[=session-observe] suppressed-lines=1"
        );
    }

    #[test]
    fn summary_stage_list_stays_bounded() {
        let root = tempfile::tempdir().expect("fixture root");
        let line = format!("{}\n", STAGE_LINES[0]);
        let mut contents = String::new();
        for _ in 0..(MAX_REPORTED_STAGES + 3) {
            contents.push_str(&line);
        }
        write_log(root.path(), contents.as_bytes());
        let observation = observe_writer_log(root.path()).expect("observation");
        assert!(!observation.overflow);
        assert_eq!(
            observation.summary.matches("=secret-inspect").count(),
            MAX_REPORTED_STAGES
        );
        assert!(observation.summary.contains("stages-omitted=3"));
    }

    /// The live twin is the single source of the emitted stage vocabulary;
    /// this diagnostics vocabulary must match it exactly or sanitized
    /// summaries silently lose stage evidence.
    #[test]
    fn diagnostics_vocabulary_matches_the_live_writer_module() {
        let emitted = emitted_stage_literals(LIVE_WRITER_SOURCE);
        assert_eq!(emitted.len(), STAGE_LINES.len());
        let live: std::collections::BTreeSet<&str> = emitted.into_iter().collect();
        let audited: std::collections::BTreeSet<&str> = STAGE_LINES.iter().copied().collect();
        assert_eq!(
            live, audited,
            "diagnostics vocabulary drifted from the live twin"
        );
    }

    const LIVE_WRITER_SOURCE: &str =
        include_str!("../../../runne-cli/src/cli/provider_credential_broker/writer_stage_live.rs");

    fn emitted_stage_literals(source: &str) -> Vec<&str> {
        let mut literals = Vec::new();
        for line in source.lines() {
            let Some(start) = line.find("eprintln!(\"") else {
                continue;
            };
            let rest = &line[start + "eprintln!(\"".len()..];
            if let Some(end) = rest.find('"') {
                literals.push(&rest[..end]);
            }
        }
        literals
    }

    const SECRET: &str = "slice-e-canary-9f2c7b";
}
