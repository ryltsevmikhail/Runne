import { describe, expect, it, vi } from 'vitest'
import {
  getManagedAttentionSnapshot, listManagedTaskRuns, prepareManagedTaskRun,
  recoverManagedTaskRun, startManagedTaskRun,
} from './managed-task-run'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const recoveryToken = '018f2e3a-7000-7000-8000-000000000214'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
const authority = {
  provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
  model: { status: 'unavailable', reason: 'runtime_projection_missing' },
  policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
}
const preflight = {
  status: 'ready', generation: 4, projectId, workspaceId, conversationId,
  canStart: true, startUnavailableReason: null, authority,
  draftPolicy: 'memory_only', recoveryToken,
}
const summary = { taskRunId, workspaceId, conversationId, state: 'succeeded', terminal: 'failure', streamVersion: 2, activeAttemptId: null }

describe('managed TaskRun public DTOs', () => {
  it('preserves native-authorized scope while explicitly reporting display authority unavailable', async () => {
    const invoke = vi.fn(async () => preflight)
    await expect(prepareManagedTaskRun(projectId, workspaceId, invoke)).resolves.toEqual(preflight)
    expect(invoke).toHaveBeenCalledWith('prepare_managed_task_run', { projectId, workspaceId })
    await expect(prepareManagedTaskRun(projectId, taskRunId, async () => ({ ...preflight, projectId: workspaceId }))).rejects.toThrow('Invalid managed TaskRun preflight')
    await expect(prepareManagedTaskRun(projectId, workspaceId, async () => ({ ...preflight, effectiveAuthority: { ...authority, model: { ...authority.model, privateModelId: 'secret' } } }))).rejects.toThrow('Invalid managed TaskRun preflight')
  })

  it('sends one typed start request and rejects a noncanonical acknowledgement version', async () => {
    const request = { workspaceId, conversationId, prompt: 'Build a feature', generation: 4, recoveryToken }
    const ack = { status: 'accepted', taskRunId, streamVersion: 2, recoveryToken }
    const invoke = vi.fn(async () => ack)
    await expect(startManagedTaskRun(request, invoke)).resolves.toEqual(ack)
    expect(invoke).toHaveBeenCalledTimes(1)
    expect(invoke).toHaveBeenCalledWith('start_managed_task_run', request)
    await expect(startManagedTaskRun(request, async () => ({ ...ack, streamVersion: 3 }))).rejects.toThrow('Invalid managed TaskRun acknowledgement')
  })

  it('reads recovery by the same opaque token and validates normalized scope before route decisions', async () => {
    const accepted = { status: 'accepted', taskRunId, streamVersion: 2, workspaceId, conversationId }
    const invoke = vi.fn(async () => accepted)
    await expect(recoverManagedTaskRun(recoveryToken, invoke)).resolves.toEqual(accepted)
    expect(invoke).toHaveBeenCalledWith('recover_managed_task_run', { recoveryToken })
    await expect(recoverManagedTaskRun(recoveryToken, async () => ({ ...accepted, conversationId: projectId }))).resolves.toMatchObject({ conversationId: projectId })
    await expect(recoverManagedTaskRun(recoveryToken, async () => ({ status: 'accepted', taskRunId, streamVersion: 2 }))).rejects.toThrow('Invalid managed TaskRun recovery response')
    await expect(recoverManagedTaskRun(recoveryToken, async () => ({ status: 'unknown', taskRunId }))).rejects.toThrow('Invalid managed TaskRun recovery response')
  })

  it('rejects malformed or duplicate inventory snapshots rather than making a partial tree', async () => {
    await expect(listManagedTaskRuns(async () => ({ status: 'available', taskRuns: [summary] }))).resolves.toEqual({ status: 'available', taskRuns: [summary] })
    await expect(listManagedTaskRuns(async () => ({ status: 'available', taskRuns: [{ ...summary, state: 'invented' }] }))).rejects.toThrow('Invalid managed TaskRun inventory')
    await expect(listManagedTaskRuns(async () => ({ status: 'available', taskRuns: [{ ...summary, terminal: 'happy' }] }))).rejects.toThrow('Invalid managed TaskRun inventory')
    await expect(listManagedTaskRuns(async () => ({ status: 'available', taskRuns: [summary, summary] }))).rejects.toThrow('Invalid managed TaskRun inventory')
  })

  it('accepts bounded attention projections with scoped links and explicit authority summaries', async () => {
    const snapshot = { status: 'available', complete: false, items: [
      { approvalId: recoveryToken, taskRunId, kind: 'approval', workspaceId: null, conversationId: null },
      { approvalId: null, taskRunId, kind: 'uncertain', workspaceId, conversationId },
      { approvalId: null, taskRunId: null, kind: 'effective_authority_unavailable', workspaceId: null, conversationId: null },
      { approvalId: null, taskRunId: null, kind: 'effects_unavailable', workspaceId: null, conversationId: null },
    ] }
    await expect(getManagedAttentionSnapshot(async () => snapshot)).resolves.toEqual(snapshot)
    await expect(getManagedAttentionSnapshot(async () => ({ ...snapshot, items: [{ ...snapshot.items[0], kind: 'approval', workspaceId }] }))).rejects.toThrow('Invalid managed attention snapshot')
    await expect(getManagedAttentionSnapshot(async () => ({ status: 'available', complete: false, items: [{ ...snapshot.items[2], taskRunId }] }))).rejects.toThrow('Invalid managed attention snapshot')
  })
})
