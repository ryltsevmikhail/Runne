import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft, ManagedTaskDraftClear, ManagedTaskDraftWrite } from '@/entities/task-run/api/managed-task-draft'
import type { DraftApi } from '../model/draft-session'
import { prepareManagedTaskRun, recoverManagedTaskRun, startManagedTaskRun } from '@/entities/task-run/api/managed-task-run'
import type { ManagedTaskRunPreflight } from '@/entities/task-run/api/managed-task-run'
import TaskComposer from './TaskComposer.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const recoveryToken = '018f2e3a-7000-7000-8000-000000000214'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
const scopeToken = 'a'.repeat(64)

class MemoryStorage implements Storage {
  private values = new Map<string, string>()
  get length() { return this.values.size }
  clear() { this.values.clear() }
  getItem(key: string) { return this.values.get(key) ?? null }
  key(index: number) { return [...this.values.keys()][index] ?? null }
  removeItem(key: string) { this.values.delete(key) }
  setItem(key: string, value: string) { this.values.set(key, String(value)) }
}
class DraftStore {
  revision = 0
  prompt: string | null = null
  scopeToken = 'a'.repeat(64)
  loadResult: Promise<ManagedTaskDraft> | null = null
  clearFailures = 0
  holdNextSave = false
  finishHeldSave: (() => void) | null = null
  readonly events: string[] = []
  readonly api: DraftApi = {
    load: vi.fn(async () => { this.events.push('load'); return this.loadResult ?? this.snapshot() }),
    save: vi.fn(async (_project: string, _workspace: string, write: ManagedTaskDraftWrite) => this.save(write)),
    clear: vi.fn(async (_project: string, _workspace: string, clear: ManagedTaskDraftClear) => this.clear(clear)),
  }
  snapshot(): ManagedTaskDraft { return { revision: this.revision, prompt: this.prompt, scopeToken: this.scopeToken } }
  private save(write: ManagedTaskDraftWrite): Promise<ManagedTaskDraft> {
    this.events.push('save')
    if (write.scopeToken !== this.scopeToken || write.expectedRevision !== this.revision) throw new ManagedTaskDraftError('conflict')
    if (this.holdNextSave) {
      this.holdNextSave = false
      return new Promise(resolve => {
        this.finishHeldSave = () => {
          this.revision += 1
          this.prompt = write.prompt
          resolve(this.snapshot())
        }
      })
    }
    this.revision += 1
    this.prompt = write.prompt
    return Promise.resolve(this.snapshot())
  }
  private clear(clear: ManagedTaskDraftClear): ManagedTaskDraft {
    this.events.push('clear')
    if (this.clearFailures > 0) { this.clearFailures -= 1; throw new ManagedTaskDraftError('unavailable') }
    if (clear.scopeToken !== this.scopeToken) throw new ManagedTaskDraftError('conflict')
    if (this.prompt === null && this.revision > clear.expectedRevision) return this.snapshot()
    if (clear.expectedRevision !== this.revision) throw new ManagedTaskDraftError('conflict')
    this.revision += 1
    this.prompt = null
    return this.snapshot()
  }
}

const storage = new MemoryStorage()
const mounted: Array<{ unmount: () => void }> = []
const authority = {
  provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
  model: { status: 'unavailable', reason: 'runtime_projection_missing' },
  policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
} as const
const ready: ManagedTaskRunPreflight = {
  status: 'ready', generation: 7, projectId, workspaceId, conversationId,
  canStart: true, startUnavailableReason: null, authority, draftPolicy: 'protected_restart', recoveryToken,
}

async function render(options: {
  draft: DraftStore
  projectId?: string
  workspaceId?: string
  start?: typeof startManagedTaskRun
  recover?: typeof recoverManagedTaskRun
  prepare?: typeof prepareManagedTaskRun
  disabled?: boolean
  preserveStorage?: boolean
}) {
  const renderedProjectId = options.projectId ?? projectId
  const renderedWorkspaceId = options.workspaceId ?? workspaceId
  if (options.preserveStorage !== true) storage.clear()
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div>Workspace</div>' } },
    { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div>Timeline</div>' } },
  ] })
  await router.push(`/workspaces/${renderedWorkspaceId}`); await router.isReady()
  const wrapper = mount(TaskComposer, { props: {
    projectId: renderedProjectId, workspaceId: renderedWorkspaceId, storage, draftApi: options.draft.api,
    prepare: options.prepare ?? vi.fn(async (requestedProject, requestedWorkspace) => ({
      ...ready, projectId: requestedProject, workspaceId: requestedWorkspace,
    } as ManagedTaskRunPreflight)),
    disabled: options.disabled ?? false,
    ...(options.start === undefined ? {} : { start: options.start }),
    ...(options.recover === undefined ? {} : { recover: options.recover }),
  }, global: { plugins: [router] } })
  mounted.push(wrapper)
  await flushPromises()
  return { wrapper, router }
}

beforeEach(() => storage.clear())
afterEach(() => { for (const wrapper of mounted.splice(0)) wrapper.unmount() })

describe('protected task draft recovery', () => {
  it('revalidates same-policy identity after disable and before unchanged-text submit', async () => {
    const store = new DraftStore()
    store.revision = 1
    store.prompt = 'principal A text'
    const start = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }))
    const prepare = vi.fn(async () => ready)
    const { wrapper } = await render({ draft: store, start, prepare })
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('principal A text')
    await wrapper.setProps({ disabled: true })

    store.scopeToken = 'b'.repeat(64)
    store.revision = 3
    store.prompt = 'principal B text'
    let finishLoad: ((draft: ManagedTaskDraft) => void) | undefined
    store.loadResult = new Promise(resolve => { finishLoad = resolve })
    await wrapper.setProps({ disabled: false })
    await vi.waitFor(() => expect(store.events.filter(event => event === 'load')).toHaveLength(2))
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    finishLoad?.({ revision: 3, prompt: 'principal B text', scopeToken: store.scopeToken })
    store.loadResult = null
    await vi.waitFor(() => expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('principal B text'))
    expect(wrapper.get('textarea').attributes('disabled')).toBeUndefined()

    store.scopeToken = 'c'.repeat(64)
    store.revision = 1
    store.prompt = 'principal C text'
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(start).not.toHaveBeenCalled()
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('principal C text')
    await vi.waitFor(() => expect(prepare).toHaveBeenCalledTimes(3))
    expect(wrapper.text()).not.toContain('The start result is uncertain')
  })

  it('keeps an oversized prompt editable without autosaving, then saves a repaired prompt', async () => {
    const store = new DraftStore()
    const { wrapper } = await render({ draft: store })
    const oversized = 'x'.repeat(64 * 1024 + 1)
    await wrapper.get('textarea').setValue(oversized)
    await new Promise(resolve => setTimeout(resolve, 300))
    expect(wrapper.get('textarea').attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).toContain('Task text must be 64 KiB or less.')
    expect(store.events).not.toContain('save')
    await wrapper.get('textarea').setValue('repaired prompt')
    await vi.waitFor(() => expect(store.prompt).toBe('repaired prompt'))
  })

  it('restores an acknowledged draft after a full renderer reload without using localStorage', async () => {
    const store = new DraftStore()
    const first = await render({ draft: store })
    await first.wrapper.get('textarea').setValue('Private saved draft')
    await vi.waitFor(() => expect(store.prompt).toBe('Private saved draft'))
    expect(storage.getItem(`runne:managed-task-run:${workspaceId}`)).toBeNull()
    expect([...Array(storage.length)].map((_, index) => storage.getItem(storage.key(index) ?? '')).join('')).not.toContain('Private saved draft')
    first.wrapper.unmount()
    store.events.length = 0
    const reloaded = await render({ draft: store, preserveStorage: true })
    expect((reloaded.wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('Private saved draft')
    expect(store.events).toEqual(['load'])
  })

  it('hides the old scope synchronously while its pending save drains', async () => {
    const store = new DraftStore()
    const workspaceB = '018f2e3a-7000-7000-8000-000000000218'
    const projectB = '018f2e3a-7000-7000-8000-000000000217'
    const prepare = vi.fn(async (requestedProject: string, requestedWorkspace: string) => ({
      ...ready,
      projectId: requestedProject,
      workspaceId: requestedWorkspace,
      draftPolicy: requestedWorkspace === workspaceId ? 'protected_restart' as const : 'memory_only' as const,
    }))
    const { wrapper } = await render({ draft: store, prepare })
    await wrapper.get('textarea').setValue('saved A text')
    await vi.waitFor(() => expect(store.prompt).toBe('saved A text'))

    store.holdNextSave = true
    await wrapper.get('textarea').setValue('stalled A plaintext')
    await vi.waitFor(() => expect(store.finishHeldSave).not.toBeNull())
    await wrapper.setProps({ projectId: projectB, workspaceId: workspaceB })
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).not.toContain('stalled A plaintext')
    expect(wrapper.text()).not.toContain('Unsubmitted task text is encrypted on this device')
    expect(wrapper.text()).not.toContain('Saving draft securely')

    store.finishHeldSave?.()
    await vi.waitFor(() => expect(wrapper.text()).toContain('Unsubmitted task text stays in memory'))
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
    expect(wrapper.text()).not.toContain('stalled A plaintext')
    expect(store.prompt).toBe('stalled A plaintext')
  })

  it('flushes a durable revision before dispatch and binds recovery only to opaque draft identity', async () => {
    const store = new DraftStore()
    const start = vi.fn(async () => {
      store.events.push('start')
      return { status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }
    })
    const { wrapper } = await render({ draft: store, start })
    await wrapper.get('textarea').setValue('Submission prompt')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(store.events.indexOf('save')).toBeLessThan(store.events.indexOf('clear'))
    expect(store.events.indexOf('save')).toBeLessThan(store.events.indexOf('start'))
    expect(store.events.indexOf('start')).toBeLessThan(store.events.indexOf('clear'))
    expect(start).toHaveBeenCalledTimes(1)
    const binding = JSON.parse(storage.getItem(`runne:managed-task-run:${workspaceId}`) ?? '{}') as Record<string, unknown>
    expect(binding).toMatchObject({ draftScopeToken: scopeToken, draftRevision: 1, acceptedTaskRunId: taskRunId })
    expect(JSON.stringify(binding)).not.toContain('Submission prompt')
  })

  it('prioritizes a lost-ack binding after reload and never loads or submits its draft again', async () => {
    const store = new DraftStore()
    const first = await render({ draft: store, start: async () => { throw new Error('ack lost') }, recover: async () => uncertain() })
    await first.wrapper.get('textarea').setValue('Never resubmit this')
    await first.wrapper.get('form').trigger('submit'); await flushPromises()
    expect(first.wrapper.text()).toContain('The start result is uncertain')
    expect(JSON.stringify(storage.getItem(`runne:managed-task-run:${workspaceId}`))).not.toContain('Never resubmit this')
    first.wrapper.unmount()
    store.events.length = 0
    const start = vi.fn()
    const recover = vi.fn(async () => uncertain())
    const second = await render({ draft: store, start, recover, preserveStorage: true })
    expect(recover).toHaveBeenCalledTimes(1)
    expect(start).not.toHaveBeenCalled()
    expect(store.events).toEqual([])
    expect(second.wrapper.text()).toContain('The start result is uncertain')
  })

  it('keeps the accepted blocker after clear failure and retries idempotent cleanup', async () => {
    const store = new DraftStore()
    store.clearFailures = 1
    const start = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }))
    const { wrapper } = await render({ draft: store, start })
    await wrapper.get('textarea').setValue('Accepted prompt')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(start).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('Retry before starting another task')
    expect(wrapper.findAll('button').some(button => button.text() === 'Start a new task')).toBe(false)
    const retryCleanup = wrapper.findAll('button').find(button => button.text().includes('Retry draft cleanup'))
    expect(retryCleanup).toBeDefined()
    await retryCleanup?.trigger('click'); await flushPromises()
    expect(start).toHaveBeenCalledTimes(1)
    expect(store.prompt).toBeNull()
    expect(wrapper.text()).toContain('Start a new task')
  })

  it('preserves a newer sibling-window revision when accepted cleanup hits a CAS conflict', async () => {
    const store = new DraftStore()
    let acknowledge: (() => void) | undefined
    const start = vi.fn(() => new Promise<{ status: 'accepted', taskRunId: string, streamVersion: 2, recoveryToken: string }>(resolve => {
      acknowledge = () => resolve({ status: 'accepted', taskRunId, streamVersion: 2, recoveryToken })
    }))
    const first = await render({ draft: store, start })
    await first.wrapper.get('textarea').setValue('Submitted revision')
    await vi.waitFor(() => expect(store.prompt).toBe('Submitted revision'))
    const sibling = await render({ draft: store, preserveStorage: true })
    await first.wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(start).toHaveBeenCalledTimes(1))
    await sibling.wrapper.get('textarea').setValue('Newer sibling revision')
    await vi.waitFor(() => expect(store.prompt).toBe('Newer sibling revision'))
    acknowledge?.()
    await flushPromises()
    expect(first.wrapper.text()).toContain('A newer draft from another window was preserved')
    expect((first.wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('Newer sibling revision')
    expect(store.prompt).toBe('Newer sibling revision')
    expect(first.wrapper.text()).toContain('Start a new task')
  })
})

function uncertain() {
  return { status: 'uncertain' as const, taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }
}
