use runne_app_core::RuntimeAvailability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Bootstrap,
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    State,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Live,
    Transient,
    Terminal,
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Observation {
    operation: Operation,
    outcome: Outcome,
    disposition: Disposition,
    runtime: Option<RuntimeAvailability>,
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
impl Operation {
    const fn code(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Connect => "connect",
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
impl Outcome {
    const fn code(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Rejected => "rejected",
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
impl Disposition {
    const fn code(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Transient => "transient",
            Self::Terminal => "terminal",
        }
    }
}

pub const fn disposition_for(runtime: Option<RuntimeAvailability>) -> Disposition {
    match runtime {
        Some(RuntimeAvailability::Live) => Disposition::Live,
        Some(RuntimeAvailability::Reconnecting | RuntimeAvailability::Reconciling) => {
            Disposition::Transient
        }
        _ => Disposition::Terminal,
    }
}

pub fn disposition_from_ipc(value: &str) -> Disposition {
    match value {
        "live" => Disposition::Live,
        "transient" => Disposition::Transient,
        _ => Disposition::Terminal,
    }
}

pub fn record(
    operation: Operation,
    outcome: Outcome,
    disposition: Disposition,
    runtime: Option<RuntimeAvailability>,
) {
    #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
    record_qualification(Observation {
        operation,
        outcome,
        disposition,
        runtime,
    });

    #[cfg(not(all(target_os = "linux", feature = "linux-native-enrollment-qualification")))]
    let _ = (operation, outcome, disposition, runtime);
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
fn record_qualification(observation: Observation) {
    use std::io::Write as _;
    use std::sync::{Mutex, OnceLock};

    static LAST: OnceLock<Mutex<Option<Observation>>> = OnceLock::new();
    static COUNT: OnceLock<Mutex<u16>> = OnceLock::new();
    let last = LAST.get_or_init(|| Mutex::new(None));
    let count = COUNT.get_or_init(|| Mutex::new(0));
    let Ok(mut previous) = last.lock() else {
        return;
    };
    if *previous == Some(observation) {
        return;
    }
    let Ok(mut emitted) = count.lock() else {
        return;
    };
    if *emitted >= 256 {
        return;
    }
    *previous = Some(observation);
    *emitted += 1;
    let runtime = observation.runtime.map_or("unknown", runtime_code);
    let _ = writeln!(
        std::io::stderr().lock(),
        "runne-desktop-qualification operation={} outcome={} disposition={} runtime={runtime}",
        observation.operation.code(),
        observation.outcome.code(),
        observation.disposition.code(),
    );
}

#[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
const fn runtime_code(runtime: RuntimeAvailability) -> &'static str {
    match runtime {
        RuntimeAvailability::Unconfigured => "unconfigured",
        RuntimeAvailability::ProfileLoaded => "profile_loaded",
        RuntimeAvailability::PeerVerified => "peer_verified",
        RuntimeAvailability::BootstrapProved => "bootstrap_proved",
        RuntimeAvailability::Authenticated => "authenticated",
        RuntimeAvailability::Reconciling => "reconciling",
        RuntimeAvailability::Live => "live",
        RuntimeAvailability::Reconnecting => "reconnecting",
        RuntimeAvailability::Incompatible => "incompatible",
        RuntimeAvailability::Revoked => "revoked",
        RuntimeAvailability::ResyncRequired => "resync_required",
        RuntimeAvailability::Fatal => "fatal",
    }
}

#[cfg(test)]
mod tests {
    use super::{Disposition, disposition_for, disposition_from_ipc};
    use runne_app_core::RuntimeAvailability;

    #[test]
    fn disposition_is_closed_and_defaults_unknown_to_terminal() {
        assert_eq!(
            disposition_for(Some(RuntimeAvailability::Live)),
            Disposition::Live
        );
        assert_eq!(
            disposition_for(Some(RuntimeAvailability::Reconnecting)),
            Disposition::Transient
        );
        assert_eq!(
            disposition_for(Some(RuntimeAvailability::Reconciling)),
            Disposition::Transient
        );
        assert_eq!(
            disposition_for(Some(RuntimeAvailability::ResyncRequired)),
            Disposition::Terminal
        );
        assert_eq!(disposition_for(None), Disposition::Terminal);
        assert_eq!(disposition_from_ipc("transient"), Disposition::Transient);
        assert_eq!(disposition_from_ipc("terminal"), Disposition::Terminal);
        assert_eq!(disposition_from_ipc("unexpected"), Disposition::Terminal);
    }
}
