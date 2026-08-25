//! Runtime-owned process and bounded terminal-output contracts.

use runne_domain::id::{
    AttemptId, CommandId, IdempotencyKey, InvocationId, ProcessId, TaskRunId, WorkspaceId,
};

/// Capability required before process lifecycle operations are available.
pub const PROCESS_CONTROL_CAPABILITY_V1: &str = "process.control.v1";
/// Maximum UTF-8 bytes in one sanitized output chunk.
pub const MAX_PROCESS_OUTPUT_BYTES: usize = 64 * 1024;
/// Maximum chunks returned by one output page.
pub const MAX_PROCESS_OUTPUT_CHUNKS: u16 = 128;
/// Conservative encoded response budget for one output page.
pub const MAX_PROCESS_OUTPUT_WIRE_BYTES: usize = 7 * 1024 * 1024;
const MAX_PROCESS_OUTPUT_CHUNK_OVERHEAD_BYTES: usize = 128;

/// Authenticated identity and idempotency context for process mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessCommandContext {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Caller idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated principal.
    pub principal: crate::ApiPrincipalId,
    /// Actor recorded by the runtime.
    pub actor: crate::ApiActor,
}

/// Authenticated owner context required for process queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessQueryContext {
    /// Authenticated principal whose owned process may be queried.
    pub principal: crate::ApiPrincipalId,
}

/// Runtime-owned invocation to start; no executable path or renderer argv crosses this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartProcessCommand {
    /// Authoritative Workspace.
    pub workspace_id: WorkspaceId,
    /// Owning TaskRun.
    pub task_run_id: TaskRunId,
    /// Exact active attempt.
    pub attempt_id: AttemptId,
    /// One-time runtime-prepared invocation.
    pub invocation_id: InvocationId,
}

/// Exact process lifecycle mutation target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExistingProcessCommand {
    /// Runtime-owned process.
    pub process_id: ProcessId,
    /// Version expected by the caller.
    pub expected_version: u64,
}

/// Closed process lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
}

/// Sanitized process snapshot without PID, native handle or raw OS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSnapshot {
    /// Runtime-owned process identity.
    pub process_id: ProcessId,
    /// Runtime-owned invocation.
    pub invocation_id: InvocationId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Exact lifecycle state.
    pub state: ProcessState,
    /// Monotonic process version.
    pub version: u64,
    /// Next bounded output cursor.
    pub next_output_sequence: u64,
}

/// Output stream after runtime-side terminal sanitization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputStream {
    Stdout,
    Stderr,
}

/// One bounded, ordered, plain-text process output chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutputChunk {
    sequence: u64,
    stream: ProcessOutputStream,
    text: String,
}

impl ProcessOutputChunk {
    /// Creates a chunk and rejects control/ANSI material.
    pub fn new(
        sequence: u64,
        stream: ProcessOutputStream,
        text: impl Into<String>,
    ) -> Result<Self, ProcessHostError> {
        let text = text.into();
        if sequence == 0 {
            return Err(ProcessHostError::InvariantViolation);
        }
        if text.len() > MAX_PROCESS_OUTPUT_BYTES {
            return Err(ProcessHostError::SizeLimit);
        }
        if text.chars().any(is_disallowed_output_character) {
            return Err(ProcessHostError::InvalidOutput);
        }
        Ok(Self {
            sequence,
            stream,
            text,
        })
    }
    /// Returns the monotonic sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Returns the output stream.
    #[must_use]
    pub const fn stream(&self) -> ProcessOutputStream {
        self.stream
    }
    /// Returns sanitized plain text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One bounded page of ordered process output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutputPage {
    chunks: Vec<ProcessOutputChunk>,
}

impl ProcessOutputPage {
    /// Validates page size and strict sequence ordering.
    pub fn new(limit: u16, chunks: Vec<ProcessOutputChunk>) -> Result<Self, ProcessHostError> {
        if limit == 0 || limit > MAX_PROCESS_OUTPUT_CHUNKS || chunks.len() > usize::from(limit) {
            return Err(ProcessHostError::InvalidLimit);
        }
        let wire_bytes = chunks.iter().try_fold(0_usize, |total, chunk| {
            total
                .checked_add(encoded_text_bytes(chunk.text()))
                .and_then(|total| total.checked_add(MAX_PROCESS_OUTPUT_CHUNK_OVERHEAD_BYTES))
        });
        if wire_bytes.is_none_or(|bytes| bytes > MAX_PROCESS_OUTPUT_WIRE_BYTES) {
            return Err(ProcessHostError::SizeLimit);
        }
        chunks
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
            .then_some(Self { chunks })
            .ok_or(ProcessHostError::InvariantViolation)
    }
    /// Returns the ordered chunks.
    #[must_use]
    pub fn chunks(&self) -> &[ProcessOutputChunk] {
        &self.chunks
    }
}

fn is_disallowed_output_character(character: char) -> bool {
    (character.is_control() && !matches!(character, '\n' | '\t'))
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn encoded_text_bytes(text: &str) -> usize {
    text.bytes().fold(0, |total, byte| {
        total
            + if matches!(byte, b'"' | b'\\' | b'\n' | b'\t') {
                2
            } else {
                1
            }
    })
}

/// Closed process host failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessHostError {
    InvalidLimit,
    InvalidOutput,
    NotFound,
    Conflict,
    Forbidden,
    Backpressure,
    SizeLimit,
    Unavailable,
    InvariantViolation,
}

/// Runtime-owned process and output boundary.
pub trait ProcessHostPort: Send + Sync {
    /// Starts one pre-authorized runtime invocation.
    fn start_process(
        &self,
        context: ProcessCommandContext,
        command: StartProcessCommand,
    ) -> impl std::future::Future<Output = Result<ProcessSnapshot, ProcessHostError>> + Send;
    /// Reads one sanitized snapshot.
    fn get_process(
        &self,
        context: ProcessQueryContext,
        process_id: ProcessId,
    ) -> impl std::future::Future<Output = Result<ProcessSnapshot, ProcessHostError>> + Send;
    /// Reads one bounded output page after the supplied cursor.
    fn read_process_output(
        &self,
        context: ProcessQueryContext,
        process_id: ProcessId,
        after_sequence: u64,
        limit: u16,
    ) -> impl std::future::Future<Output = Result<ProcessOutputPage, ProcessHostError>> + Send;
    /// Requests stop for the exact expected process version.
    fn stop_process(
        &self,
        context: ProcessCommandContext,
        command: ExistingProcessCommand,
    ) -> impl std::future::Future<Output = Result<ProcessSnapshot, ProcessHostError>> + Send;
}
