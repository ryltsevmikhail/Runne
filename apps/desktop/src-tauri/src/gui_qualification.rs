use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use runne_app_core::{AppCore, ManagedTaskRunRecovery, ManagedTaskRunStart};
use serde_json::json;
use tauri::Manager;

#[path = "gui_qualification_connect.rs"]
mod connect;
#[path = "gui_qualification_page_script.rs"]
mod page_script;

const QUALIFICATION_PROFILE: [u8; 32] = [0xD2; 32];
const PREVIOUS_TOKEN_SENTINEL: &str = "__d2_gui_qualification_previous_token__";
const DRAFT_PROBE_TOKEN: &str = "018f2e3a-7000-7000-8000-000000000299";
const DRAFT_PROMPT: &str = "DX1 protected draft reload qualification prompt";

/// Closed, test-support-only configuration for the native lost-ACK scenario.
#[derive(Clone)]
pub struct GuiQualificationControl {
    root: PathBuf,
    phase: String,
    project_id: String,
    workspace_id: String,
}

impl GuiQualificationControl {
    pub fn from_env() -> Result<Self, String> {
        let root = env_path("RUNNE_D2_GUI_FIXTURE_ROOT")?;
        let root = fs::canonicalize(root).map_err(|_| "fixture root unavailable")?;
        let metadata = fs::metadata(&root).map_err(|_| "fixture root unavailable")?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("fixture root must be a private directory".to_owned());
        }
        for name in ["XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME"] {
            let configured = fs::canonicalize(env_path(name)?)
                .map_err(|_| "isolated XDG directory unavailable")?;
            if !configured.starts_with(&root) {
                return Err("XDG paths must remain inside the fixture root".to_owned());
            }
        }
        let phase =
            std::env::var("RUNNE_D2_GUI_FIXTURE_PHASE").map_err(|_| "fixture phase missing")?;
        if !["draft-save", "draft-reload", "lost-ack", "recover", "fresh"].contains(&phase.as_str())
        {
            return Err("fixture phase invalid".to_owned());
        }
        let project_id = canonical_id("RUNNE_D2_GUI_PROJECT_ID")?;
        let workspace_id = canonical_id("RUNNE_D2_GUI_WORKSPACE_ID")?;
        fs::create_dir_all(root.join("markers"))
            .map_err(|_| "fixture marker directory unavailable")?;
        let control = Self {
            root,
            phase,
            project_id,
            workspace_id,
        };
        if !control.root.join("start-handler-count").exists() {
            control.write_secret("start-handler-count", b"0")?;
        }
        Ok(control)
    }

    pub(crate) fn open_core(&self, profile_directory: &Path) -> Result<AppCore, String> {
        if !profile_directory.starts_with(&self.root) {
            return Err("Tauri profile escaped fixture root".to_owned());
        }
        let core = runne_app_core::test_support::open_anchored_external_local_core_with_persistent_fixture(
            &profile_directory.join("profile.sqlite3"),
            &profile_directory.join("secure-anchor"),
            QUALIFICATION_PROFILE,
        ).map_err(|_| "anchored fixture AppCore unavailable")?;
        Ok(core)
    }

    pub(crate) fn before_start(&self) -> Result<(), String> {
        let count = fs::read_to_string(self.root.join("start-handler-count"))
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("start handler count overflow")?;
        self.write_secret("start-handler-count", count.to_string().as_bytes())
    }

    pub(crate) async fn after_start(
        &self,
        core: &AppCore,
        result: &ManagedTaskRunStart,
    ) -> Result<(), String> {
        if result.status != "accepted" {
            return Ok(());
        }
        let task_run_id = result
            .task_run_id
            .as_deref()
            .ok_or("accepted receipt omitted TaskRun id")?;
        let inventory = core
            .list_managed_task_runs()
            .await
            .map_err(|_| "canonical TaskRun inventory unavailable")?;
        let task_run_count = inventory.task_runs.len();
        let start_call_count = self.read_start_call_count()?;
        if self.phase == "lost-ack" {
            self.write_secret("original-recovery-token", result.recovery_token.as_bytes())?;
        }
        self.write_marker(
            &format!("accepted-{}.json", self.phase),
            &json!({
                "phase": self.phase,
                "taskRunId": task_run_id,
            "streamVersion": result.stream_version,
            "taskRunCount": task_run_count,
            "startHandlerCalls": start_call_count,
                "receipt": "accepted-after-commit",
            }),
        )?;
        if self.phase == "lost-ack" {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    pub(crate) async fn after_recovery(
        &self,
        core: &AppCore,
        requested_token: &str,
        result: &ManagedTaskRunRecovery,
    ) -> Result<(), String> {
        if self.phase == "recover" && requested_token == PREVIOUS_TOKEN_SENTINEL {
            return self.write_marker(
                "recovered-current-rendered.json",
                &json!({
                    "phase": self.phase,
                    "status": result.status,
                    "taskRunId": result.task_run_id,
                    "checkpoint": "rendered-accepted-task-run",
                }),
            );
        }
        if self.phase == "draft-save" && requested_token == DRAFT_PROBE_TOKEN {
            return self
                .write_draft_marker(core, "draft-saved.json", false)
                .await;
        }
        if self.phase == "draft-reload" && requested_token == DRAFT_PROBE_TOKEN {
            return self
                .write_draft_marker(core, "draft-restored.json", true)
                .await;
        }
        let name = if requested_token == PREVIOUS_TOKEN_SENTINEL {
            "recovered-original.json"
        } else {
            "recovered-current.json"
        };
        let inventory = core
            .list_managed_task_runs()
            .await
            .map_err(|_| "canonical TaskRun inventory unavailable")?;
        let start_call_count = self.read_start_call_count()?;
        self.write_marker(
            name,
            &json!({
                "phase": self.phase,
                "status": result.status,
                "taskRunId": result.task_run_id,
                "streamVersion": result.stream_version,
                "workspaceId": result.workspace_id,
                    "conversationId": result.conversation_id,
                    "taskRunCount": inventory.task_runs.len(),
                    "startHandlerCalls": start_call_count,
            }),
        )
    }

    pub(crate) fn recovery_token(&self) -> Result<String, String> {
        fs::read_to_string(self.root.join("original-recovery-token"))
            .map_err(|_| "original recovery receipt unavailable".to_owned())
    }

    fn read_start_call_count(&self) -> Result<u64, String> {
        fs::read_to_string(self.root.join("start-handler-count"))
            .map_err(|_| "start handler counter unavailable".to_owned())?
            .parse()
            .map_err(|_| "start handler counter corrupt".to_owned())
    }

    pub(crate) fn page_script(&self) -> String {
        page_script::build(&self.phase, &self.workspace_id)
    }

    async fn write_draft_marker(
        &self,
        core: &AppCore,
        marker: &str,
        restored: bool,
    ) -> Result<(), String> {
        let draft = core
            .load_managed_task_draft(&self.project_id, &self.workspace_id)
            .await
            .map_err(|_| "protected GUI draft unavailable")?;
        let draft_matches = draft.prompt.as_deref() == Some(DRAFT_PROMPT);
        if !draft_matches || draft.revision == 0 {
            return Err("protected GUI draft was not durably saved".to_owned());
        }
        let inventory = core
            .list_managed_task_runs()
            .await
            .map_err(|_| "TaskRun inventory unavailable")?;
        let start_call_count = self.read_start_call_count()?;
        self.write_marker(
            marker,
            &json!({
                "phase": self.phase,
                "draftMatches": draft_matches,
                "draftRevision": draft.revision,
                "taskRunCount": inventory.task_runs.len(),
                "startHandlerCalls": start_call_count,
                "restored": restored,
            }),
        )
    }

    fn write_secret(&self, name: &str, value: &[u8]) -> Result<(), String> {
        let path = self.root.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "fixture token write failed")?;
        file.write_all(value)
            .and_then(|()| file.sync_all())
            .map_err(|_| "fixture token write failed")?;
        Ok(())
    }

    fn write_marker(&self, name: &str, value: &serde_json::Value) -> Result<(), String> {
        let path = self.root.join("markers").join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "fixture marker write failed")?;
        file.write_all(value.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "fixture marker write failed")?;
        Ok(())
    }
}

pub fn on_page_load<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    payload: &tauri::webview::PageLoadPayload<'_>,
) {
    if !matches!(payload.event(), tauri::webview::PageLoadEvent::Finished) {
        return;
    }
    if let Some(control) = webview.try_state::<GuiQualificationControl>() {
        let _ = webview.eval(control.page_script());
    }
}

pub const fn previous_token_sentinel() -> &'static str {
    PREVIOUS_TOKEN_SENTINEL
}

fn env_path(name: &str) -> Result<PathBuf, String> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} missing"))
}

fn canonical_id(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} missing"))?;
    runne_app_core::CanonicalId::parse(&value).map_err(|_| format!("{name} invalid"))?;
    Ok(value)
}
