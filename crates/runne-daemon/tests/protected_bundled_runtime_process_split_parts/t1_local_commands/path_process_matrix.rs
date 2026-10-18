use std::path::PathBuf;

#[path = "path_process_matrix/effects.rs"]
mod effects;
#[path = "path_process_matrix/python_child.rs"]
mod python_child;
#[path = "path_process_matrix/requests.rs"]
mod requests;

const CHILD_ARGUMENT_WITH_SPACES: &str = "argument with spaces";
const CHILD_ARGUMENT_WITH_QUOTES: &str = "value with 'single' and \"double\" quotes";
const CHILD_ENV_NAME: &str = "RUNNE_TEST_PATH_MATRIX_ONLY";
const CHILD_ENV_VALUE: &str = "fixture-only value with 'quotes'";
const CROSS_VOLUME_SEED: &str = "cross-volume-input\n";

pub(super) struct PathProcessMatrix {
    workspace: PathBuf,
    fixture_cwd: PathBuf,
    fixture_cwd_relative: String,
    sibling: PathBuf,
    symlink_target: PathBuf,
    symlink_in_workspace: PathBuf,
    hardlink_source: PathBuf,
    hardlink_in_sibling: PathBuf,
    rename_source: PathBuf,
    rename_target: PathBuf,
    replace_source: PathBuf,
    replace_target: PathBuf,
    case_upper: PathBuf,
    case_lower: PathBuf,
    case_log: PathBuf,
    child_marker: PathBuf,
    python_script: PathBuf,
    python_stderr: PathBuf,
    python_source: String,
    hidden_device_directory: tempfile::TempDir,
    hidden_device_source: PathBuf,
    cross_volume_directory: tempfile::TempDir,
    cross_volume_source: PathBuf,
    cross_volume_output: PathBuf,
    cross_volume_link_target: PathBuf,
    cross_volume_rename_target: PathBuf,
}
