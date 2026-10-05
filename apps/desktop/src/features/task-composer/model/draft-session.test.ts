import { describe, expect, it, vi } from 'vitest'
import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft } from '@/entities/task-run/api/managed-task-draft'
import type { DraftApi } from './draft-session'
import { DraftSession } from './draft-session'
import { DraftStore, otherToken, projectId, session, token, workspaceId } from './draft-session-test-support'

describe('managed draft session', () => {
  it('serializes edits made while an acknowledged save is in flight', async () => {
    const store = new DraftStore()
    store.holdSaves = true
    const draft = session(store)
    await draft.open('protected_restart')
    draft.edit('first edit')
    const firstFlush = draft.flush()
    await vi.waitFor(() => expect(store.saves).toHaveLength(1))
    draft.edit('newer edit')
    const secondFlush = draft.flush()
    expect(store.saves[0]?.write.expectedRevision).toBe(0)
    store.saves[0]?.finish({ revision: 1, prompt: 'first edit', scopeToken: token })
    await vi.waitFor(() => expect(store.saves).toHaveLength(2))
    expect(store.saves[1]?.write.expectedRevision).toBe(1)
    store.saves[1]?.finish({ revision: 2, prompt: 'newer edit', scopeToken: token })
    await Promise.all([firstFlush, secondFlush])
    expect(draft.view.status).toBe('saved')
    expect(draft.view.revision).toBe(2)
    expect(draft.view.prompt).toBe('newer edit')
  })

  it('preserves local edits through delayed same-token revalidation', async () => {
    const store = new DraftStore()
    store.current = { revision: 3, prompt: 'saved A', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    draft.edit('local edit A')
    let finishLoad: ((draft: ManagedTaskDraft) => void) | undefined
    store.loadResult = new Promise(resolve => { finishLoad = resolve })
    const loading = draft.open('protected_restart')
    expect(draft.view.prompt).toBe('')
    finishLoad?.({ revision: 3, prompt: 'saved A', scopeToken: token })
    await loading
    expect(draft.view.prompt).toBe('local edit A')
    expect(draft.view.status).toBe('unsaved')
    await draft.release()
  })

  it('discards local text when same IDs now resolve to another durable identity', async () => {
    const store = new DraftStore()
    store.current = { revision: 2, prompt: 'principal A saved text', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    draft.edit('principal A local text')
    store.current = { revision: 4, prompt: 'principal B saved text', scopeToken: otherToken }
    await draft.open('protected_restart')
    expect(draft.view.prompt).toBe('principal B saved text')
    expect(draft.view.scopeToken).toBe(otherToken)
    expect(store.writeCalls).toBe(0)
  })

  it('adopts clean remote text and makes dirty local text reconcile after same-token revision drift', async () => {
    const store = new DraftStore()
    store.current = { revision: 2, prompt: 'saved A', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    store.current = { revision: 3, prompt: 'sibling newer text', scopeToken: token }
    await draft.open('protected_restart')
    expect(draft.view.prompt).toBe('sibling newer text')
    expect(draft.view.status).toBe('saved')
    draft.edit('local unsaved A')
    store.current = { revision: 4, prompt: 'another sibling update', scopeToken: token }
    await draft.open('protected_restart')
    expect(draft.view.prompt).toBe('local unsaved A')
    expect(draft.view.status).toBe('conflict')
    expect(store.writeCalls).toBe(0)
  })

  it('revalidates unchanged text before returning a submit token', async () => {
    const store = new DraftStore()
    store.current = { revision: 2, prompt: 'unchanged A text', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    store.current = { revision: 5, prompt: 'B text', scopeToken: otherToken }
    await expect(draft.flush()).rejects.toMatchObject({ code: 'conflict' })
    expect(draft.view.prompt).toBe('')
    expect(draft.view.policy).toBe('unknown')
    expect(draft.view.scopeToken).toBeNull()
    expect(store.writeCalls).toBe(0)
  })

  it('treats a same-prompt newer revision as a submit conflict', async () => {
    const store = new DraftStore()
    store.current = { revision: 2, prompt: 'unchanged A text', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    store.current = { revision: 3, prompt: 'unchanged A text', scopeToken: token }
    await expect(draft.flush()).rejects.toMatchObject({ code: 'conflict' })
    expect(draft.view.status).toBe('conflict')
    expect(store.writeCalls).toBe(0)
  })

  it('scrubs and revalidates when typed native scope validation changes', async () => {
    const store = new DraftStore()
    let refreshed: unknown
    const api: DraftApi = {
      ...store.api,
      save: async () => { throw new ManagedTaskDraftError('scope_changed') },
    }
    const draft = new DraftSession(api, 60_000, scope => { refreshed = scope })
    draft.begin({ projectId, workspaceId })
    await draft.open('protected_restart')
    draft.edit('old identity plaintext')
    await expect(draft.flush()).rejects.toMatchObject({ code: 'scope_changed' })
    expect(draft.view.prompt).toBe('')
    expect(draft.view.scopeToken).toBeNull()
    expect(draft.view.policy).toBe('unknown')
    expect(refreshed).toEqual({ projectId, workspaceId })
  })

  it('leaves oversized edits editable and skips autosave until repaired', async () => {
    const store = new DraftStore()
    const draft = new DraftSession(store.api, 5)
    draft.begin({ projectId, workspaceId })
    await draft.open('protected_restart')
    draft.edit('x'.repeat(64 * 1024 + 1))
    await new Promise(resolve => setTimeout(resolve, 20))
    expect(draft.view.status).toBe('unsaved')
    expect(store.writeCalls).toBe(0)
    draft.edit('repaired prompt')
    await draft.release()
    expect(store.current.prompt).toBe('repaired prompt')
    expect(store.writeCalls).toBe(1)
  })

  it('fences delayed loads and saves when the active scope changes', async () => {
    const store = new DraftStore()
    let finishLoad: ((draft: ManagedTaskDraft) => void) | undefined
    store.loadResult = new Promise(resolve => { finishLoad = resolve })
    const draft = session(store)
    const oldLoad = draft.open('protected_restart')
    draft.begin({ projectId, workspaceId: '018f2e3a-7000-7000-8000-000000000216' })
    store.loadResult = null
    await draft.open('protected_restart')
    finishLoad?.({ revision: 7, prompt: 'stale text', scopeToken: otherToken })
    await oldLoad
    expect(draft.view.prompt).toBe('')
    expect(draft.view.scopeToken).toBe(token)
  })

  it('preserves a newer revision after accepted cleanup conflicts', async () => {
    const store = new DraftStore()
    store.current = { revision: 4, prompt: 'submitted', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    store.current = { revision: 5, prompt: 'newer sibling draft', scopeToken: token }
    await expect(draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: token, revision: 4 })).resolves.toBe('newer')
    expect(draft.view.prompt).toBe('newer sibling draft')
    expect(store.current.prompt).toBe('newer sibling draft')
    expect(store.clears).toEqual([{ scopeToken: token, expectedRevision: 4 }])
  })

  it('scrubs the old identity when conflict reconciliation detects a token change', async () => {
    const store = new DraftStore()
    store.current = { revision: 1, prompt: 'saved A', scopeToken: token }
    const draft = session(store)
    await draft.open('protected_restart')
    draft.edit('local A text')
    store.current = { revision: 2, prompt: 'sibling A text', scopeToken: token }
    await draft.open('protected_restart')
    expect(draft.view.status).toBe('conflict')

    store.current = { revision: 3, prompt: 'saved B text', scopeToken: otherToken }
    await draft.reconcileConflict('keep_local')
    expect(draft.view.prompt).toBe('')
    expect(draft.view.scopeToken).toBeNull()
    expect(draft.view.policy).toBe('unknown')
    expect(store.writeCalls).toBe(0)
  })

  it('scrubs the old identity when accepted cleanup discovers a token flip', async () => {
    let reads = 0
    const api: DraftApi = {
      load: async () => {
        reads += 1
        return reads < 3
          ? { revision: 4, prompt: 'submitted A text', scopeToken: token }
          : { revision: 1, prompt: 'saved B text', scopeToken: otherToken }
      },
      save: async () => { throw new Error('unexpected save') },
      clear: async () => { throw new ManagedTaskDraftError('conflict') },
    }
    const draft = new DraftSession(api, 60_000)
    draft.begin({ projectId, workspaceId })
    await draft.open('protected_restart')
    await expect(draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: token, revision: 4 })).resolves.toBe('blocked')
    expect(draft.view.prompt).toBe('')
    expect(draft.view.scopeToken).toBeNull()
    expect(draft.view.policy).toBe('unknown')
  })

  it('does not let late token-mismatch cleanup scrub a newer scope', async () => {
    let reads = 0
    let finishReconcile: ((draft: ManagedTaskDraft) => void) | undefined
    const api: DraftApi = {
      load: async () => {
        reads += 1
        if (reads === 3) return new Promise(resolve => { finishReconcile = resolve })
        return { revision: 4, prompt: 'submitted A text', scopeToken: token }
      },
      save: async () => { throw new Error('unexpected save') },
      clear: async () => { throw new ManagedTaskDraftError('conflict') },
    }
    const draft = new DraftSession(api, 60_000)
    draft.begin({ projectId, workspaceId })
    await draft.open('protected_restart')
    const cleanup = draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: token, revision: 4 })
    await vi.waitFor(() => expect(finishReconcile).toBeDefined())

    draft.begin({ projectId, workspaceId: '018f2e3a-7000-7000-8000-000000000216' })
    await draft.open('memory_only')
    draft.edit('current B text')
    finishReconcile?.({ revision: 1, prompt: 'saved B text', scopeToken: otherToken })
    await expect(cleanup).resolves.toBe('blocked')
    expect(draft.view.prompt).toBe('current B text')
    expect(draft.view.policy).toBe('memory_only')
  })

  it('leaves accepted cleanup blocked when native clear is unavailable', async () => {
    const store = new DraftStore()
    store.current = { revision: 2, prompt: 'submitted', scopeToken: token }
    store.failClear = true
    const draft = session(store)
    await draft.open('protected_restart')
    await expect(draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: token, revision: 2 })).resolves.toBe('blocked')
    expect(draft.view.status).toBe('error')
  })

  it('ignores delayed accepted-cleanup rejection after begin changes the scope', async () => {
    let rejectOldLoad: ((error: Error) => void) | undefined
    let reads = 0
    const api: DraftApi = {
      load: async () => {
        reads += 1
        if (reads === 1) return new Promise((_, reject) => { rejectOldLoad = reject })
        return { revision: 0, prompt: null, scopeToken: otherToken }
      },
      save: async () => { throw new Error('unexpected save') },
      clear: async () => { throw new ManagedTaskDraftError('conflict') },
    }
    const draft = new DraftSession(api, 60_000)
    draft.begin({ projectId, workspaceId })
    const cleanup = draft.clearSubmitted({ projectId, workspaceId }, { scopeToken: token, revision: 1 })
    await vi.waitFor(() => expect(rejectOldLoad).toBeDefined())
    draft.begin({ projectId, workspaceId: '018f2e3a-7000-7000-8000-000000000216' })
    rejectOldLoad?.(new Error('late load failure'))
    await expect(cleanup).resolves.toBe('blocked')
    await draft.open('protected_restart')
    expect(draft.view.status).toBe('saved')
    expect(draft.view.error).toBeNull()
    expect(draft.view.scopeToken).toBe(otherToken)
  })

  it('fences a held save acknowledgement across an A-to-B-to-A scope cycle', async () => {
    const store = new DraftStore()
    store.holdSaves = true
    const draft = session(store)
    await draft.open('protected_restart')
    draft.edit('old A text')
    const oldSave = draft.flush()
    await vi.waitFor(() => expect(store.saves).toHaveLength(1))
    draft.begin({ projectId, workspaceId: '018f2e3a-7000-7000-8000-000000000216' })
    draft.begin({ projectId, workspaceId })
    const reopening = draft.open('protected_restart')
    store.saves[0]?.reject(new ManagedTaskDraftError('unavailable'))
    await expect(oldSave).rejects.toBeInstanceOf(ManagedTaskDraftError)
    await reopening
    expect(draft.view.prompt).toBe('')
    expect(draft.view.status).toBe('saved')
    expect(store.current.prompt).toBeNull()
    expect(store.saves).toHaveLength(1)
  })
})
