import { describe, expect, it } from 'vitest'

import { getTaskRunEffects, isTaskRunEffects, type TaskRunEffects } from './task-run-effects'

const taskRunId = '018f47a2-7a12-7abc-8abc-123456789abc'
const base: TaskRunEffects = {
  taskRunId,
  streamVersion: 9,
  attemptId: null,
  cancellationRequested: true,
  localCommand: null,
  remote: {
    outcome: 'unknown',
    publication: 'unknown',
    accounting: 'unknown',
    cancellation: 'requested',
    availability: 'unavailable',
    capabilities: { statusCheck: true, streamResume: false, remoteCancel: true },
    usageKnown: null,
  },
  successor: 'requires_duplicate_effect_acknowledgment',
}

describe('TaskRun effects API', () => {
  it('keeps a factual remote completion separate from a cancellation request', async () => {
    const value = { ...base, remote: { ...base.remote, outcome: 'completed' as const, publication: 'withheld' as const } }
    const result = await getTaskRunEffects(taskRunId, async (command, args) => {
      expect(command).toBe('get_task_run_effects')
      expect(args).toEqual({ taskRunId })
      return value
    })
    expect(result.remote.outcome).toBe('completed')
    expect(result.remote.cancellation).toBe('requested')
    expect(result.remote.publication).toBe('withheld')
  })

  it('rejects cross-version identity, inferred cancellation, and unknown fields', () => {
    expect(isTaskRunEffects({ ...base, streamVersion: 0 }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, privateResponseText: 'hidden' }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, remote: { ...base.remote, cancellation: 'confirmed' } }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, remote: { ...base.remote, publication: 'withheld' } }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, localCommand: { outcome: 'exited', stop: 'confirmed', exitCode: null } }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, localCommand: { outcome: 'running', stop: 'confirmed', exitCode: null } }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, localCommand: { outcome: 'exited', stop: 'confirmed', exitCode: 2147483648 } }, taskRunId)).toBe(false)
    expect(isTaskRunEffects({ ...base, localCommand: { outcome: 'exited', stop: 'confirmed', exitCode: -2147483649 } }, taskRunId)).toBe(false)
  })

  it('keeps confirmed local stop distinct from an unknown remote outcome', () => {
    const value = {
      ...base,
      localCommand: { outcome: 'outcome_unknown' as const, stop: 'confirmed' as const, exitCode: null },
    }
    expect(isTaskRunEffects(value, taskRunId)).toBe(true)
    if (isTaskRunEffects(value, taskRunId)) {
      expect(value.localCommand?.stop).toBe('confirmed')
      expect(value.remote.outcome).toBe('unknown')
    }
  })

  it('accepts fresh remote running with accepted cancellation still unconfirmed', async () => {
    const value = {
      ...base,
      remote: {
        ...base.remote,
        outcome: 'running' as const,
        publication: 'unknown' as const,
        accounting: 'unknown' as const,
        cancellation: 'unconfirmed' as const,
        usageKnown: null,
      },
    }
    const result = await getTaskRunEffects(taskRunId, async () => value)
    expect(result.remote.outcome).toBe('running')
    expect(result.remote.cancellation).toBe('unconfirmed')
    expect(result.remote.usageKnown).toBeNull()
    expect(isTaskRunEffects({
      ...value,
      remote: { ...value.remote, cancellation: 'confirmed' as const },
    }, taskRunId)).toBe(false)
  })
})

it('accepts already-terminal cancellation only with completed remote outcome', () => {
  const remote = { ...base.remote, outcome: 'completed', cancellation: 'already_terminal' }
  expect(isTaskRunEffects({ ...base, remote }, taskRunId)).toBe(true)
  expect(isTaskRunEffects({ ...base, remote, cancellationRequested: false }, taskRunId)).toBe(false)
  expect(isTaskRunEffects({ ...base, remote: { ...remote, outcome: 'unknown' } }, taskRunId)).toBe(false)
  expect(isTaskRunEffects({ ...base, remote: { ...remote, outcome: 'running' } }, taskRunId)).toBe(false)
})
