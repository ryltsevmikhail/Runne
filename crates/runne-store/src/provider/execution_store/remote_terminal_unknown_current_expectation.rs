struct UnknownCurrentExpectation<'a> {
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
    conversation_id: ConversationId,
    attempt: &'a ExecutionAttempt,
    original_principal: &'a str,
    grant_digest: Option<[u8; 32]>,
    grant_active: bool,
}
