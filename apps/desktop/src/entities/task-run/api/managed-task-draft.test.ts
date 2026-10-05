import { describe, expect, it, vi } from 'vitest'
import { clearManagedTaskDraft, loadManagedTaskDraft, ManagedTaskDraftError, saveManagedTaskDraft } from './managed-task-draft'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const scopeToken = 'a'.repeat(64)
const draft = { revision: 4, prompt: 'Private draft', scopeToken }

describe('managed task draft API', () => {
  it('strictly validates the scope-bound DTO and forwards opaque CAS identity', async () => {
    const invoke = vi.fn(async () => draft)
    await expect(loadManagedTaskDraft(projectId, workspaceId, invoke)).resolves.toEqual(draft)
    expect(invoke).toHaveBeenCalledWith('load_managed_task_draft', { projectId, workspaceId })
    await expect(saveManagedTaskDraft(projectId, workspaceId, { scopeToken, expectedRevision: 4, prompt: 'Next' }, invoke)).resolves.toEqual(draft)
    expect(invoke).toHaveBeenLastCalledWith('save_managed_task_draft', {
      projectId, workspaceId, scopeToken, expectedRevision: 4, prompt: 'Next',
    })
    await expect(clearManagedTaskDraft(projectId, workspaceId, { scopeToken, expectedRevision: 4 }, invoke)).resolves.toEqual(draft)
  })

  it('rejects extra fields, unsafe revisions, and malformed scope tokens', async () => {
    await expect(loadManagedTaskDraft(projectId, workspaceId, async () => ({ ...draft, lineage: 'private' }))).rejects.toBeInstanceOf(ManagedTaskDraftError)
    await expect(loadManagedTaskDraft(projectId, workspaceId, async () => ({ ...draft, revision: Number.MAX_SAFE_INTEGER + 1 }))).rejects.toBeInstanceOf(ManagedTaskDraftError)
    await expect(saveManagedTaskDraft(projectId, workspaceId, { scopeToken: 'bad', expectedRevision: 0, prompt: 'x' })).rejects.toBeInstanceOf(ManagedTaskDraftError)
  })

  it('maps CAS conflict and lifetime capacity into visible typed failures', async () => {
    await expect(clearManagedTaskDraft(projectId, workspaceId, { scopeToken, expectedRevision: 4 }, async () => {
      throw 'managed_task_draft_conflict'
    })).rejects.toMatchObject({ code: 'conflict' })
    await expect(saveManagedTaskDraft(projectId, workspaceId, { scopeToken, expectedRevision: 4, prompt: 'x' }, async () => {
      throw 'managed_task_draft_capacity'
    })).rejects.toMatchObject({ code: 'capacity' })
  })

  it('preserves native identity replacement as a distinct IPC error', async () => {
    await expect(saveManagedTaskDraft(projectId, workspaceId, { scopeToken, expectedRevision: 4, prompt: 'x' }, async () => {
      throw { code: 'managed_task_draft_scope_changed' }
    })).rejects.toMatchObject({ code: 'scope_changed' })
  })
})
