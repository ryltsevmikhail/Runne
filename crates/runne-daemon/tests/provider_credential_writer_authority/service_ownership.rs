//! Occupied-label classification for the temporary credential service.
//!
//! `launchctl print` environment markers identify a job that claims to be a
//! slice-E fixture, but they are claims, not an ownership or staleness
//! proof: any same-uid peer can write the same markers, and a foreign
//! fixture root string does not show that the job is dead rather than
//! paused between scenarios. There is no reliable ownership protocol
//! available to this test, so the bootstrap performs no automatic bootout
//! of an occupied label at all: every occupied case fails closed with a
//! precise diagnostic, and a leftover fixture job is removed by hand
//! (`launchctl bootout gui/<uid>/com.runne.credential-service`) when the
//! printed report really does describe a dead fixture.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum OccupiedLabel {
    /// A live pid is attached to the label.
    LiveProcess(u32),
    /// No fixture markers: possibly a real installed service.
    NotFixtureOwned,
    /// Markers point at the current run's fixture root.
    CurrentFixtureRoot,
    /// Both fixture markers with a foreign root: claims to be another
    /// fixture run. Not proven stale — still never removed automatically.
    ForeignFixtureRoot,
    /// Markers are incomplete or contradictory.
    Ambiguous,
}

pub(super) fn classify_occupied_label(
    print_report: &str,
    current_fixture_root: &str,
) -> OccupiedLabel {
    if let Some(pid) = live_pid(print_report) {
        return OccupiedLabel::LiveProcess(pid);
    }
    let fixture_root = environment_value(print_report, "RUNNE_SLICE_E_FIXTURE_ROOT");
    let enrollment = environment_value(print_report, "RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST");
    match (fixture_root, enrollment) {
        (Some(root), Some("1")) => {
            if root == current_fixture_root {
                OccupiedLabel::CurrentFixtureRoot
            } else {
                OccupiedLabel::ForeignFixtureRoot
            }
        }
        (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => OccupiedLabel::Ambiguous,
        (None, None) => OccupiedLabel::NotFixtureOwned,
    }
}

fn live_pid(report: &str) -> Option<u32> {
    report.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|pid| *pid != 0)
    })
}

fn environment_value<'a>(report: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name} => ");
    report.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(&prefix)
            .map(|value| value.trim_end())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_ROOT: &str = "/var/folders/xx/runne-slice-e-CURRENT";
    const STALE_ROOT: &str = "/var/folders/xx/runne-slice-e-STALE";

    fn fixture_report(root: &str) -> String {
        format!(
            "\tprogram = /path/Runne.app/Contents/MacOS/runne-credential-service\n\
             \tenvironment = {{\n\
             \t\tHOME => /users/runner\n\
             \t\tRUNNE_CI_MACOS_KEYCHAIN => {root}/runne-ci.keychain-db\n\
             \t\tRUNNE_LOCAL_NATIVE_ENROLLMENT_TEST => 1\n\
             \t\tRUNNE_SLICE_E_FIXTURE_ROOT => {root}\n\
             \t}}\n"
        )
    }

    #[test]
    fn foreign_root_with_markers_and_no_pid_is_not_proven_stale() {
        assert_eq!(
            classify_occupied_label(&fixture_report(STALE_ROOT), CURRENT_ROOT),
            OccupiedLabel::ForeignFixtureRoot
        );
    }

    #[test]
    fn live_pid_is_reported_even_with_foreign_fixture_markers() {
        let report = format!("{}\tpid = 54321\n", fixture_report(STALE_ROOT));
        assert_eq!(
            classify_occupied_label(&report, CURRENT_ROOT),
            OccupiedLabel::LiveProcess(54321)
        );
    }

    #[test]
    fn missing_markers_mean_not_fixture_owned() {
        let report = "\tprogram = /Applications/Runne.app/Contents/MacOS/runned\n";
        assert_eq!(
            classify_occupied_label(report, CURRENT_ROOT),
            OccupiedLabel::NotFixtureOwned
        );
    }

    #[test]
    fn current_run_root_is_not_a_leftover() {
        assert_eq!(
            classify_occupied_label(&fixture_report(CURRENT_ROOT), CURRENT_ROOT),
            OccupiedLabel::CurrentFixtureRoot
        );
    }

    #[test]
    fn incomplete_marker_set_is_ambiguous() {
        let only_root =
            fixture_report(STALE_ROOT).replace("\t\tRUNNE_LOCAL_NATIVE_ENROLLMENT_TEST => 1\n", "");
        assert_eq!(
            classify_occupied_label(&only_root, CURRENT_ROOT),
            OccupiedLabel::Ambiguous
        );
        let only_flag = fixture_report(STALE_ROOT).replace(
            &format!("\t\tRUNNE_SLICE_E_FIXTURE_ROOT => {STALE_ROOT}\n"),
            "",
        );
        assert_eq!(
            classify_occupied_label(&only_flag, CURRENT_ROOT),
            OccupiedLabel::Ambiguous
        );
        let wrong_flag = fixture_report(STALE_ROOT).replace(
            "RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST => 1",
            "RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST => 0",
        );
        assert_eq!(
            classify_occupied_label(&wrong_flag, CURRENT_ROOT),
            OccupiedLabel::Ambiguous
        );
    }

    #[test]
    fn zero_or_absent_pid_still_allows_classification() {
        let zeroed = format!("\tpid = 0\n{}", fixture_report(STALE_ROOT));
        assert_eq!(
            classify_occupied_label(&zeroed, CURRENT_ROOT),
            OccupiedLabel::ForeignFixtureRoot
        );
    }

    /// The bootstrap must never launch a bootout for an occupied label:
    /// claimed markers plus a missing pid do not prove that a foreign job
    /// is a dead fixture, so no automatic cleanup path may exist at all.
    #[test]
    fn bootstrap_performs_no_bootout_of_occupied_labels() {
        let source = include_str!("service_process.rs");
        let bootout_commands = source.matches("args([\"bootout\"").count();
        let bootstrap = source
            .split("fn bootstrap")
            .nth(1)
            .and_then(|rest| rest.split("pub(super) fn shutdown").next())
            .expect("bootstrap body");
        assert_eq!(
            bootout_commands, 1,
            "the only bootout command must remain in shutdown of this run's own job"
        );
        assert!(
            !bootstrap.contains("bootout"),
            "bootstrap must fail closed on occupied labels instead of booting them out"
        );
    }
}
