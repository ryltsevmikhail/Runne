//! Diagnostic C-collector wire encoding only; no handle, signal or Store authority.
use runne_platform::process_managed_area::ManagedAreaIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Branch {
    RunningAtCrashAlreadyEmpty,
    LiveAtEntryEmptyBeforeStop,
    LiveOrphanStop,
}

impl Branch {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RunningAtCrashAlreadyEmpty => "RUNNING_AT_CRASH_ALREADY_EMPTY",
            Self::LiveAtEntryEmptyBeforeStop => "LIVE_AT_ENTRY_EMPTY_BEFORE_STOP",
            Self::LiveOrphanStop => "LIVE_ORPHAN_STOP",
        }
    }
}

pub(super) struct Record {
    pub source: [u8; 32],
    pub artifact: [u8; 32],
    // Collection nonce, not the independent scenario UUIDv7.
    pub run: [u8; 16],
    pub supervisor: u32,
    pub writer: u32,
    pub recovery: u32,
    pub native: u32,
    pub native_start: u64,
    pub area: ManagedAreaIdentity,
    pub branch: Branch,
}

impl Record {
    pub(super) fn line(&self) -> Result<String, &'static str> {
        let pids = [self.supervisor, self.writer, self.recovery, self.native];
        for (index, value) in pids.iter().enumerate() {
            if *value <= 1 || *value > i32::MAX as u32 || pids[..index].contains(value) {
                return Err("distinct guest PID values in C INT range required");
            }
        }
        if self.native_start == 0 {
            return Err("nonzero native start required");
        }
        // Full100-byte identity; its96-hex binding suffix is only an area basename.
        let area = hex::encode(self.area.to_bytes());
        let value = format!(
            concat!(
                "RUNNE_R05_COLLECTOR_PROVISIONAL_V1 source={} artifact={} run={} ",
                "supervisor={} writer={} recovery={} native={} native_start={} ",
                "area={} branch={}\n"
            ),
            hex::encode(self.source),
            hex::encode(self.artifact),
            hex::encode(self.run),
            self.supervisor,
            self.writer,
            self.recovery,
            self.native,
            self.native_start,
            area,
            self.branch.label(),
        );
        if value.len() >= 2048 || !value.is_ascii() {
            return Err("bounded ASCII canonical collector record required");
        }
        Ok(value)
    }
}
