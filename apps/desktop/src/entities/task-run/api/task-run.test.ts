import { describe, expect, it } from 'vitest'

import { cancelTaskRun, getTaskRunTimeline, submitTaskRun, supersedeUnknownTaskRun } from './task-run'

const id = '018f2e3a-7000-7000-8000-000000000210'

describe('TaskRun runtime adapter', () => {
  it('submits the canonical conversation, workspace, and prompt and accepts only the queued acknowledgement', async () => {
    const conversationId = '018f2e3a-7000-7000-8000-000000000211'
    const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
    const calls: unknown[] = []
    await expect(submitTaskRun(conversationId, workspaceId, 'implement a feature', async (command, args) => {
      calls.push([command, args])
      return { taskRunId: id, streamVersion: 2 }
    })).resolves.toEqual({ taskRunId: id, streamVersion: 2 })
    expect(calls).toEqual([['submit_task_run', { conversationId, workspaceId, prompt: 'implement a feature' }]])
    await expect(submitTaskRun(conversationId, workspaceId, 'prompt', async () => ({ taskRunId: id, streamVersion: 3 }))).rejects.toThrow('Invalid TaskRun submission response')
    await expect(submitTaskRun(conversationId, workspaceId, 'prompt', async () => ({ taskRunId: 'bad', streamVersion: 2 }))).rejects.toThrow('Invalid TaskRun submission response')
  })

  it('sends cancellation with the authoritative expected version and validates the ack', async () => {
    const calls: unknown[] = []
    await expect(cancelTaskRun(id, 4, async (command, args) => {
      calls.push([command, args])
      return { taskRunId: id, streamVersion: 5 }
    })).resolves.toEqual({ taskRunId: id, streamVersion: 5 })
    expect(calls).toEqual([['cancel_task_run', { taskRunId: id, expectedVersion: 4 }]])
    await expect(cancelTaskRun(id, 4, async () => ({ taskRunId: id, streamVersion: 4 }))).rejects.toThrow('Invalid TaskRun cancellation response')
  })

  it('sends only the explicit duplicate execution acknowledgment and accepts a distinct successor', async () => {
    const successorId = '018f2e3a-7000-7000-8000-000000000213'
    const calls: unknown[] = []
    await expect(supersedeUnknownTaskRun(id, 4, { acknowledgeDuplicateExecutionAndCost: true }, async (command, args) => {
      calls.push([command, args])
      return { predecessorTaskRunId: id, predecessorVersion: 5, taskRunId: successorId, streamVersion: 2 }
    })).resolves.toEqual({ predecessorTaskRunId: id, predecessorVersion: 5, taskRunId: successorId, streamVersion: 2 })
    expect(calls).toEqual([['supersede_unknown_task_run', {
      request: { taskRunId: id, expectedVersion: 4, acknowledgeDuplicateExecutionAndCost: true },
    }]])
    await expect(supersedeUnknownTaskRun(id, 4, { acknowledgeDuplicateExecutionAndCost: true }, async () => ({
      predecessorTaskRunId: id, predecessorVersion: 5, taskRunId: id, streamVersion: 2,
    }))).rejects.toThrow('Invalid TaskRun successor response')
  })

  it('accepts only a closed timeline response without endpoint or error fields', async () => {
    const timeline = await getTaskRunTimeline(id, async () => ({
      taskRunId: id,
      projectionRevision: 2,
      streamVersion: 3,
      state: 'running',
      activeAttemptId: '018f2e3a-7000-7000-8000-000000000211',
      terminal: null,
      entries: [{
        eventId: '018f2e3a-7000-7000-8000-000000000212',
        sequence: 1,
        committedAt: 1,
        kind: 'attempt_started',
        attemptId: '018f2e3a-7000-7000-8000-000000000211',
      }],
      recovery: 'live',
    }))

    expect(timeline.entries[0]?.kind).toBe('attempt_started')
    await expect(getTaskRunTimeline(id, async () => ({ ...timeline, endpoint: 'http://private' }))).rejects.toThrow('Invalid TaskRun response')
  })

  it('rejects a non-canonical TaskRun ID before invoking the host', async () => {
    await expect(getTaskRunTimeline('../private', async () => null)).rejects.toThrow('Invalid TaskRun identity')
  })

  it('fails closed for unknown authoritative state or timeline kind', async () => {
    const valid = await getTaskRunTimeline(id, async () => ({
      taskRunId: id, projectionRevision: 0, streamVersion: 0, state: 'running', activeAttemptId: null,
      terminal: null, entries: [], recovery: 'live',
    }))
    await expect(getTaskRunTimeline(id, async () => ({ ...valid, state: 'future_state' }))).rejects.toThrow('Invalid TaskRun response')
    await expect(getTaskRunTimeline(id, async () => ({ ...valid, entries: [{ eventId: id, sequence: 1, committedAt: 1, kind: 'future_kind', attemptId: null }] }))).rejects.toThrow('Invalid TaskRun response')
  })
})
