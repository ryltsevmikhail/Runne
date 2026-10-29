use super::Backend;

impl Backend {
    pub(super) async fn project_activity(&mut self) {
        let tasks: Vec<_> = self
            .runs
            .iter()
            .filter(|run| run.conversation_id() == self.selected)
            .rev()
            .take(4)
            .map(runne_runtime_client::TaskRunSnapshot::task_run_id)
            .collect();
        for task in tasks {
            match self.owner.client.get_task_run_tool_activity(task).await {
                Ok(activity) => {
                    for entry in activity.entries {
                        self.snapshot.actions.push(format!(
                            "{} — {} · {}",
                            entry.tool_name, entry.target, entry.state
                        ));
                        if let Some(output) = entry.result_text {
                            self.snapshot.actions.push(output);
                        }
                        if entry.truncated {
                            self.snapshot
                                .actions
                                .push("[runtime tool output truncated]".into());
                        }
                    }
                }
                Err(error) => self
                    .snapshot
                    .actions
                    .push(format!("Tool output unavailable: {error}")),
            }
        }
    }
}
