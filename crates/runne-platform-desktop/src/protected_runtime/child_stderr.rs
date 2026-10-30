// Bounded, redacted capture of one protected child's stderr.
//
// The capture only exists to explain a failed startup. It keeps a fixed-size
// tail, never blocks the child, and never formats secret-looking values.
use std::collections::VecDeque;

const MAX_CAPTURE_BYTES: usize = 8 * 1024;
const MAX_LINE_BYTES: usize = 240;
const MAX_REPORTED_LINES: usize = 8;
const MAX_REPORTED_BYTES: usize = 2 * 1024;
const READ_CHUNK_BYTES: usize = 4 * 1024;

#[derive(Default)]
struct SharedCapture {
    tail: VecDeque<u8>,
    finished: bool,
}

/// One live drain that keeps only the most recent bytes.
pub(super) struct ProtectedChildStderr {
    shared: std::sync::Arc<std::sync::Mutex<SharedCapture>>,
}

impl ProtectedChildStderr {
    pub(super) fn start(mut pipe: std::process::ChildStderr) -> Self {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(SharedCapture::default()));
        let writer = std::sync::Arc::clone(&shared);
        std::thread::spawn(move || {
            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            loop {
                let read = std::io::Read::read(&mut pipe, &mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                let Ok(mut state) = writer.lock() else {
                    break;
                };
                for byte in &chunk[..read] {
                    if state.tail.len() == MAX_CAPTURE_BYTES {
                        state.tail.pop_front();
                    }
                    state.tail.push_back(*byte);
                }
            }
            if let Ok(mut state) = writer.lock() {
                state.finished = true;
            }
        });
        Self { shared }
    }

    /// Waits at most `timeout` for the drain to observe EOF, then reports the
    /// sanitized tail. Returns `None` when nothing was captured.
    pub(super) fn report(&self, timeout: std::time::Duration) -> Option<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let finished = self
                .shared
                .lock()
                .map(|state| state.finished)
                .unwrap_or(true);
            if finished || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let bytes = self
            .shared
            .lock()
            .map(|state| state.tail.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        sanitized_tail(&bytes)
    }
}

/// Starts the bounded drain when the launcher owns the child's stderr.
pub(super) fn start_child_stderr(
    child: Option<&mut std::process::Child>,
    capture_output: bool,
) -> Option<ProtectedChildStderr> {
    if capture_output {
        return None;
    }
    child
        .and_then(|child| child.stderr.take())
        .map(ProtectedChildStderr::start)
}

/// Reaps one failed child and returns its status plus the sanitized tail.
pub(super) fn reap_failed_child(
    child: &mut Option<std::process::Child>,
    capture: Option<&ProtectedChildStderr>,
) -> Option<(std::process::ExitStatus, Option<String>)> {
    let child = child.as_mut()?;
    let _ = child.kill();
    let status = child.wait().ok()?;
    let tail = capture.and_then(|capture| capture.report(std::time::Duration::from_millis(500)));
    Some((status, tail))
}

impl ProtectedBundledRuntimeProcess {
    /// Returns the bounded, redacted stderr tail without waiting for exit.
    #[must_use]
    pub fn child_stderr_tail(&self) -> Option<String> {
        self.child_stderr
            .as_ref()
            .and_then(|capture| capture.report(std::time::Duration::from_millis(300)))
    }
}

fn sanitized_tail(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(sanitize_line)
        .collect::<Vec<_>>();
    if lines.len() > MAX_REPORTED_LINES {
        lines.drain(..lines.len() - MAX_REPORTED_LINES);
    }
    let mut reported = String::new();
    for line in lines {
        if reported.len() + line.len() + 1 > MAX_REPORTED_BYTES {
            break;
        }
        reported.push_str(&line);
        reported.push('\n');
    }
    (!reported.is_empty()).then_some(reported)
}

fn sanitize_line(line: &str) -> String {
    let mut sanitized = redact_assignments(line);
    sanitized = redact_long_tokens(&sanitized);
    truncate(&sanitized, MAX_LINE_BYTES)
}

/// Masks the value after `=`/`:` when the key names a credential.
fn redact_assignments(line: &str) -> String {
    const SENSITIVE: [&str; 8] = [
        "secret",
        "token",
        "password",
        "passwd",
        "authorization",
        "api_key",
        "apikey",
        "bearer",
    ];
    let lower = line.to_ascii_lowercase();
    let Some((index, separator)) = lower
        .char_indices()
        .find(|(_, character)| *character == '=' || *character == ':')
    else {
        return line.to_owned();
    };
    let key = lower[..index].trim_end_matches([' ', '"', '\'']);
    if !SENSITIVE
        .iter()
        .any(|name| key.ends_with(name) || key.contains(&format!("{name}_")))
    {
        return line.to_owned();
    }
    let value_start = index + separator.len_utf8();
    let mut redacted = line[..value_start].to_owned();
    redacted.push_str("<redacted>");
    redacted
}

/// Masks long opaque runs that may be keys, tokens or signatures.
fn redact_long_tokens(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut run = String::new();
    fn flush(run: &mut String, output: &mut String) {
        if run.len() >= 32 && run.chars().all(|character| character.is_ascii_alphanumeric()) {
            output.push_str("<redacted-token>");
        } else {
            output.push_str(run);
        }
        run.clear();
    }
    for character in line.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=' | '_' | '-') {
            run.push(character);
        } else {
            flush(&mut run, &mut output);
            output.push(character);
        }
    }
    flush(&mut run, &mut output);
    output
}

fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut cut = limit;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &value[..cut])
}

#[cfg(test)]
mod child_stderr_tests {
    use super::*;

    #[test]
    fn long_opaque_values_and_credential_assignments_are_redacted() {
        let line = "provider key unavailable RUNNE_API_KEY=sk-live-super-secret";
        let sanitized = sanitize_line(line);
        assert!(!sanitized.contains("sk-live"));
        assert!(sanitized.contains("provider key unavailable"));
    }

    #[test]
    fn the_tail_keeps_only_recent_bounded_lines() {
        let mut bytes = Vec::new();
        for index in 0..40 {
            bytes.extend_from_slice(format!("line-{index}\n").as_bytes());
        }
        let tail = sanitized_tail(&bytes).unwrap();
        assert!(tail.contains("line-39"));
        assert!(tail.lines().count() <= MAX_REPORTED_LINES);
        assert!(tail.len() <= MAX_REPORTED_BYTES);
    }

    #[test]
    fn ordinary_diagnostic_text_stays_readable() {
        let tail = sanitized_tail(b"admission failed: platform check rejected darwin\n").unwrap();
        assert!(tail.contains("platform check rejected darwin"));
    }
}
