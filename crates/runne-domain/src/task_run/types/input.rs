pub const MAX_TASK_RUN_PROMPT_BYTES: usize = 65_536;

/// Validated immutable user input attached to a submitted TaskRun.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunInput {
    prompt: String,
    requested_model: Option<String>,
    selected_profile: Option<SelectedProviderProfile>,
    local_command: Option<TaskRunLocalCommand>,
}

impl std::fmt::Debug for TaskRunInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskRunInput")
            .field("redacted", &true)
            .field("requested_model", &self.requested_model)
            .field("selected_profile", &self.selected_profile)
            .field("local_command", &self.local_command.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunInputError;

impl TaskRunInput {
    pub fn new(prompt: String) -> Result<Self, TaskRunInputError> {
        if prompt.trim().is_empty() || prompt.len() > MAX_TASK_RUN_PROMPT_BYTES {
            return Err(TaskRunInputError);
        }
        Ok(Self {
            prompt,
            requested_model: None,
            selected_profile: None,
            local_command: None,
        })
    }

    pub fn with_requested_model(mut self, model: String) -> Result<Self, TaskRunInputError> {
        if self.local_command.is_some()
            || model.is_empty()
            || model.len() > 256
            || !model.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TaskRunInputError);
        }
        self.requested_model = Some(model);
        Ok(self)
    }

    pub fn with_local_command(
        mut self,
        command: TaskRunLocalCommand,
    ) -> Result<Self, TaskRunInputError> {
        if self.requested_model.is_some() || self.selected_profile.is_some() {
            return Err(TaskRunInputError);
        }
        self.local_command = Some(command);
        Ok(self)
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn requested_model(&self) -> Option<&str> {
        self.requested_model.as_deref()
    }
    pub fn with_selected_profile(
        mut self,
        profile: SelectedProviderProfile,
    ) -> Result<Self, TaskRunInputError> {
        if self.local_command.is_some() {
            return Err(TaskRunInputError);
        }
        self.selected_profile = Some(profile);
        Ok(self)
    }
    pub fn selected_profile(&self) -> Option<&SelectedProviderProfile> {
        self.selected_profile.as_ref()
    }
    pub fn local_command(&self) -> Option<&TaskRunLocalCommand> {
        self.local_command.as_ref()
    }
    pub fn validate_execution_selection(&self) -> Result<(), TaskRunInputError> {
        if self.local_command.is_some()
            && (self.requested_model.is_some() || self.selected_profile.is_some())
        {
            Err(TaskRunInputError)
        } else {
            Ok(())
        }
    }
}
