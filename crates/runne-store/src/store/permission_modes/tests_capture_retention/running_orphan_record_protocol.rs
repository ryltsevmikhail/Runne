//! Closed helper framing. Parsing bytes does not prove descriptor/process state.
use serde::{Deserialize, Serialize};

pub(super) const RECORD_CAP: usize = 16384;
pub(super) const OUTPUT_CAP: usize = 16544;
pub(super) const ERROR_CAP: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Name {
    OriginalArea,
    BeforeGo,
    AfterReady,
    RunningCut,
    SupervisorAck,
    AfterAck,
    RecoveryResult,
    ControlResult,
}
impl Name {
    pub(super) fn stem(self) -> &'static str {
        match self {
            Self::OriginalArea => "original-area",
            Self::BeforeGo => "before-go",
            Self::AfterReady => "after-ready",
            Self::RunningCut => "running-cut",
            Self::SupervisorAck => "supervisor-ack",
            Self::AfterAck => "after-ack",
            Self::RecoveryResult => "recovery-result",
            Self::ControlResult => "control-result",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Publish,
    Read,
}
impl Operation {
    pub(super) fn text(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Read => "read",
        }
    }
}

pub(super) fn decode(
    bytes: &[u8],
    op: Operation,
    name: Name,
    input: usize,
) -> Result<Vec<u8>, &'static str> {
    if bytes.len() > OUTPUT_CAP {
        return Err("helper stdout cap");
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("helper header LF")?
        + 1;
    if end > 160 || !bytes[..end].is_ascii() {
        return Err("bounded ASCII helper header");
    }
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| "header UTF8")?;
    let prefix = format!(
        "R05_RECORD_HELPER_V1 op={} name={} bytes=",
        op.text(),
        name.stem()
    );
    let count = header
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(" closed=3\n"))
        .ok_or("exact helper operation/name/close roster")?;
    if count.is_empty()
        || count.len() > 5
        || count.starts_with('0')
        || !count.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("canonical helper count");
    }
    let count: usize = count.parse().map_err(|_| "helper count range")?;
    if !(1..=RECORD_CAP).contains(&count) {
        return Err("helper record cap");
    }
    let payload = &bytes[end..];
    match op {
        Operation::Publish if count == input && payload.is_empty() => Ok(Vec::new()),
        Operation::Read if input == 0 && payload.len() == count => Ok(payload.to_vec()),
        _ => Err("exact helper payload/input length"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_is_exactly_bound_and_cannot_accept_success_looking_trailing_data() {
        let publish = b"R05_RECORD_HELPER_V1 op=publish name=running-cut bytes=2 closed=3\n";
        assert_eq!(
            decode(publish, Operation::Publish, Name::RunningCut, 2),
            Ok(vec![])
        );
        let read = b"R05_RECORD_HELPER_V1 op=read name=running-cut bytes=2 closed=3\n{}";
        assert_eq!(
            decode(read, Operation::Read, Name::RunningCut, 0),
            Ok(b"{}".to_vec())
        );
        assert!(decode(publish, Operation::Publish, Name::RunningCut, 3).is_err());
        assert!(decode(publish, Operation::Publish, Name::AfterAck, 2).is_err());
        for bad in ["02", "0", "16385", "+2", "2 ", "18446744073709551616"] {
            let frame =
                format!("R05_RECORD_HELPER_V1 op=read name=running-cut bytes={bad} closed=3\n{{}}");
            assert!(decode(frame.as_bytes(), Operation::Read, Name::RunningCut, 0).is_err());
        }
        for suffix in ["\n", "{}", "\0"] {
            let mut frame = read.to_vec();
            frame.extend_from_slice(suffix.as_bytes());
            assert!(decode(&frame, Operation::Read, Name::RunningCut, 0).is_err());
        }
        let wrong = std::str::from_utf8(read)
            .unwrap()
            .replace("closed=3", "closed=2");
        assert!(decode(wrong.as_bytes(), Operation::Read, Name::RunningCut, 0).is_err());
        assert!(
            decode(
                &read[..read.len() - 1],
                Operation::Read,
                Name::RunningCut,
                0
            )
            .is_err()
        );
        assert!(
            decode(
                &vec![b'x'; OUTPUT_CAP + 1],
                Operation::Read,
                Name::RunningCut,
                0
            )
            .is_err()
        );
    }
}
