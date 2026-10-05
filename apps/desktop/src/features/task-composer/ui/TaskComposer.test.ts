import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ManagedTaskRunPreflight } from '@/entities/task-run'
import TaskComposer from './TaskComposer.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const recoveryToken = '018f2e3a-7000-7000-8000-000000000214'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
class MemoryStorage implements Storage {
  private values = new Map<string, string>()
  get length() { return this.values.size }
  clear() { this.values.clear() }
  getItem(key: string) { return this.values.get(key) ?? null }
  key(index: number) { return [...this.values.keys()][index] ?? null }
  removeItem(key: string) { this.values.delete(key) }
  setItem(key: string, value: string) { this.values.set(key, String(value)) }
}
class FailOnSecondWriteStorage extends MemoryStorage {
  private writes = 0
  setItem(key: string, value: string) {
    this.writes += 1
    if (this.writes === 2) throw new Error('quota exceeded')
    super.setItem(key, value)
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
  canStart: true, startUnavailableReason: null, authority,
  draftPolicy: 'memory_only', recoveryToken,
}
const blocked: ManagedTaskRunPreflight = {
  ...ready, status: 'unavailable', generation: null, canStart: false,
  startUnavailableReason: 'submit_capability_missing', conversationId: null, recoveryToken: null,
}

async function render(overrides: Record<string, unknown> = {}) {
  const { preserveStorage, ...props } = overrides
  if (preserveStorage !== true) storage.clear()
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div>Workspace</div>' } },
    { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div>Timeline</div>' } },
  ] })
  await router.push(`/workspaces/${workspaceId}`); await router.isReady()
  const wrapper = mount(TaskComposer, { props: { projectId, workspaceId, storage, prepare: vi.fn(async () => ready), ...props }, global: { plugins: [router] } })
  mounted.push(wrapper)
  await flushPromises()
  return { wrapper, router }
}

beforeEach(() => { storage.clear() })
afterEach(() => { for (const wrapper of mounted.splice(0)) wrapper.unmount() })

describe('managed TaskComposer', () => {
  it('shows exact unavailable authority metadata while allowing only native-authorized start', async () => {
    const start = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }))
    const { wrapper, router } = await render({ start })
    expect(wrapper.get('.task-composer__authority').text()).toBe('ProviderUnavailableModelUnavailablePolicyUnavailable')
    expect(wrapper.text()).toContain('Effective provider, model, and policy details are unavailable')
    expect(wrapper.text()).toContain('Draft held in memory; this status does not confirm restart recovery.')
    expect(wrapper.text()).not.toContain('Draft saved.')
    await wrapper.get('textarea').setValue('Do useful work')
    await wrapper.get('button[type="submit"]').trigger('click'); await flushPromises()
    expect(start).toHaveBeenCalledTimes(1)
    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
    const saved = JSON.parse(storage.getItem(`runne:managed-task-run:${workspaceId}`) ?? '{}') as Record<string, unknown>
    expect(saved.acceptedTaskRunId).toBe(taskRunId)
    expect(saved.navigated).toBe(true)
    expect(storage.getItem(`runne:managed-task-run:${workspaceId}`)).not.toContain('Do useful work')
  })

  it('keeps mutation disabled when native preflight lacks authority', async () => {
    const start = vi.fn()
    const { wrapper } = await render({ prepare: async () => blocked, start })
    await wrapper.get('textarea').setValue('Draft only')
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('Task start is unavailable')
    expect(start).not.toHaveBeenCalled()
  })

  it('uses one token and one start for duplicate clicks, then routes to the canonical timeline', async () => {
    let finish: ((value: { status: 'accepted', taskRunId: string, streamVersion: 2, recoveryToken: string }) => void) | undefined
    const start = vi.fn(() => new Promise<{ status: 'accepted', taskRunId: string, streamVersion: 2, recoveryToken: string }>(resolve => { finish = resolve }))
    const { wrapper, router } = await render({ start })
    await wrapper.get('textarea').setValue('Only once')
    const first = wrapper.get('form').trigger('submit')
    await flushPromises()
    await wrapper.get('form').trigger('submit')
    expect(start).toHaveBeenCalledTimes(1)
    expect(start).toHaveBeenCalledWith(expect.objectContaining({ recoveryToken, workspaceId, conversationId, prompt: 'Only once', generation: 7 }))
    finish?.({ status: 'accepted', taskRunId, streamVersion: 2, recoveryToken })
    await first; await flushPromises()
    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
  })

  it('fences a delayed uncertain acknowledgement after switching workspace scope', async () => {
    let finish: ((value: { status: 'uncertain', taskRunId: null, streamVersion: null, recoveryToken: string }) => void) | undefined
    const start = vi.fn(() => new Promise<{ status: 'uncertain', taskRunId: null, streamVersion: null, recoveryToken: string }>(resolve => { finish = resolve }))
    const nextProjectId = '018f2e3a-7000-7000-8000-000000000315'
    const nextWorkspaceId = '018f2e3a-7000-7000-8000-000000000316'
    const nextConversationId = '018f2e3a-7000-7000-8000-000000000317'
    const nextToken = '018f2e3a-7000-7000-8000-000000000318'
    const prepare = vi.fn(async (project: string, workspace: string) => ({
      ...ready, projectId: project, workspaceId: workspace,
      conversationId: workspace === nextWorkspaceId ? nextConversationId : conversationId,
      recoveryToken: workspace === nextWorkspaceId ? nextToken : recoveryToken,
    }))
    const recover = vi.fn()
    const { wrapper } = await render({ start, prepare, recover })
    await wrapper.get('textarea').setValue('Old workspace request')
    const submission = wrapper.get('form').trigger('submit')
    await flushPromises()

    await wrapper.setProps({ projectId: nextProjectId, workspaceId: nextWorkspaceId })
    await vi.waitFor(() => expect(wrapper.text()).toContain('Task'))
    finish?.({ status: 'uncertain', taskRunId: null, streamVersion: null, recoveryToken })
    await submission; await flushPromises()

    expect(wrapper.get('textarea').attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).not.toContain('The start result is uncertain')
    expect(recover).not.toHaveBeenCalled()
    expect(prepare).toHaveBeenLastCalledWith(nextProjectId, nextWorkspaceId)
  })

  it('reconciles uncertain start read-only and never submits again', async () => {
    const start = vi.fn(async () => { throw new Error('ack lost') })
    const recover = vi.fn(async () => ({ status: 'uncertain' as const, taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }))
    const { wrapper } = await render({ start, recover })
    await wrapper.get('textarea').setValue('Do not duplicate')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.text()).toContain('The start result is uncertain')
    expect(wrapper.get('button').text()).toBe('Check request status')
    expect(storage.getItem(`runne:managed-task-run:${workspaceId}`)).not.toContain('Do not duplicate')
    await wrapper.get('button').trigger('click')
    await vi.waitFor(() => expect(recover).toHaveBeenCalledTimes(2))
    expect(start).toHaveBeenCalledTimes(1)
    expect(recover).toHaveBeenCalledTimes(2)
  })

  it('restores accepted identity after reload without persisting prompt or submitting', async () => {
    storage.setItem(`runne:managed-task-run:${workspaceId}`, JSON.stringify({ recoveryToken, projectId, workspaceId, conversationId }))
    const start = vi.fn()
    const recover = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, workspaceId, conversationId }))
    const { wrapper, router } = await render({ start, recover, preserveStorage: true })
    await flushPromises()
    expect(recover).toHaveBeenCalledWith(recoveryToken)
    expect(start).not.toHaveBeenCalled()
    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
    expect(wrapper.text()).not.toContain('Private draft')
  })

  it('keeps only an in-memory unsubmitted draft and clears it on a simulated full reload', async () => {
    const first = await render()
    await first.wrapper.get('textarea').setValue('Private draft')
    expect(first.wrapper.text()).toContain('Unsubmitted task text stays in memory')
    expect(storage.getItem(`runne:managed-task-run:${workspaceId}`)).toBeNull()
    first.wrapper.unmount()
    const reloaded = await render({ preserveStorage: true })
    expect((reloaded.wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
  })

  it('reuses persisted recovery identity in a second renderer and does not create another start', async () => {
    const firstStart = vi.fn(async () => ({ status: 'uncertain' as const, taskRunId: null, streamVersion: null, recoveryToken }))
    const firstRecover = vi.fn(async () => ({ status: 'uncertain' as const, taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }))
    const first = await render({ start: firstStart, recover: firstRecover })
    await first.wrapper.get('textarea').setValue('Shared intent')
    await first.wrapper.get('button[type="submit"]').trigger('click'); await flushPromises()
    first.wrapper.unmount()

    const prepare = vi.fn(async () => ready)
    const secondStart = vi.fn()
    const recover = vi.fn(async () => ({ status: 'not_committed' as const, taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }))
    const second = await render({ preserveStorage: true, prepare, start: secondStart, recover })
    expect(recover).toHaveBeenCalledWith(recoveryToken)
    expect(prepare).not.toHaveBeenCalled()
    expect(secondStart).not.toHaveBeenCalled()
    expect(second.wrapper.text()).toContain('The start result is uncertain')
  })

  it('preserves a sibling window draft when another renderer accepts, until explicit new-task action', async () => {
    const firstStart = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }))
    const first = await render({ start: firstStart })
    const prepare = vi.fn(async () => ready)
    const secondStart = vi.fn()
    const second = await render({ preserveStorage: true, prepare, start: secondStart })
    await first.wrapper.get('textarea').setValue('Shared intent')
    await second.wrapper.get('textarea').setValue('Distinct sibling draft')
    await first.wrapper.get('button[type="submit"]').trigger('click'); await flushPromises()

    const key = `runne:managed-task-run:${workspaceId}`
    await second.wrapper.get('button[type="submit"]').trigger('click'); await flushPromises()
    window.dispatchEvent(new StorageEvent('storage', { key, newValue: storage.getItem(key) }))
    await flushPromises()
    expect(second.wrapper.text()).toContain('This task was accepted')
    expect((second.wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('Distinct sibling draft')
    expect(second.wrapper.find(`a[href="/task-runs/${taskRunId}"]`).exists()).toBe(true)
    expect(prepare).toHaveBeenCalledTimes(1)
    expect(secondStart).not.toHaveBeenCalled()
    expect(JSON.parse(storage.getItem(key) ?? '{}').recoveryToken).toBe(recoveryToken)

    await second.wrapper.get('button').trigger('click'); await flushPromises()
    expect(prepare).toHaveBeenCalledTimes(2)
    expect(storage.getItem(key)).toBeNull()
    expect((second.wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('Distinct sibling draft')
    first.wrapper.unmount(); second.wrapper.unmount()
  })

  it('keeps accepted state and routes by canonical ID when persisting the accepted receipt fails', async () => {
    const flakyStorage = new FailOnSecondWriteStorage()
    const start = vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken }))
    const { wrapper, router } = await render({ storage: flakyStorage, start })
    await wrapper.get('textarea').setValue('Accepted before persistence failure')
    await wrapper.get('form').trigger('submit'); await flushPromises()

    expect(start).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('This task was accepted')
    expect(wrapper.text()).toContain('Local recovery details could not be saved')
    expect(wrapper.text()).not.toContain('The start request was not started')
    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
  })

  it('does not let a late accepted response overwrite a newer pending identity', async () => {
    let acknowledge: ((value: { status: 'accepted', taskRunId: string, streamVersion: 2, recoveryToken: string }) => void) | undefined
    const start = vi.fn(() => new Promise<{ status: 'accepted', taskRunId: string, streamVersion: 2, recoveryToken: string }>(resolve => { acknowledge = resolve }))
    const recover = vi.fn(async () => ({ status: 'uncertain' as const, taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }))
    const { wrapper, router } = await render({ start, recover })
    await wrapper.get('textarea').setValue('Original intent')
    const submission = wrapper.get('form').trigger('submit')
    await flushPromises()

    const newer = { recoveryToken: '018f2e3a-7000-7000-8000-000000000215', projectId, workspaceId, conversationId }
    const key = `runne:managed-task-run:${workspaceId}`
    storage.setItem(key, JSON.stringify(newer))
    window.dispatchEvent(new StorageEvent('storage', { key, newValue: JSON.stringify(newer) }))
    await flushPromises()
    expect(recover).toHaveBeenCalledWith(newer.recoveryToken)
    expect(JSON.parse(storage.getItem(key) ?? '{}')).toEqual(newer)
    acknowledge?.({ status: 'accepted', taskRunId, streamVersion: 2, recoveryToken })
    await submission; await flushPromises()

    expect(JSON.parse(storage.getItem(key) ?? '{}')).toEqual(newer)
    expect(router.currentRoute.value.path).toBe(`/workspaces/${workspaceId}`)
    expect(wrapper.text()).toContain('The start result is uncertain')
    expect(wrapper.text()).not.toContain('This task was accepted')
    expect(wrapper.text()).not.toContain('Start a new task')
    expect(wrapper.get('button').text()).toBe('Check request status')
    expect(start).toHaveBeenCalledTimes(1)
  })

  it('does not start after runtime authority becomes unavailable during preflight', async () => {
    let resolve: ((value: ManagedTaskRunPreflight) => void) | undefined
    const prepare = vi.fn(() => new Promise<ManagedTaskRunPreflight>(done => { resolve = done }))
    const start = vi.fn()
    const { wrapper } = await render({ prepare, start })
    await wrapper.setProps({ disabled: true })
    resolve?.(ready); await flushPromises()
    await wrapper.get('textarea').setValue('Stale authority')
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(start).not.toHaveBeenCalled()
  })

  it('does not let a late start error from the previous workspace alter the new scope', async () => {
    let reject: ((error: Error) => void) | undefined
    const start = vi.fn(() => new Promise<never>((_, fail) => { reject = fail }))
    const recover = vi.fn()
    const { wrapper, router } = await render({ start, recover })
    await wrapper.get('textarea').setValue('Old scope')
    const submission = wrapper.get('button[type="submit"]').trigger('click')
    await flushPromises()
    await wrapper.setProps({ projectId: '018f2e3a-7000-7000-8000-000000000215', workspaceId: '018f2e3a-7000-7000-8000-000000000216' })
    reject?.(new Error('late failure'))
    await submission; await flushPromises()
    expect(recover).not.toHaveBeenCalled()
    expect(router.currentRoute.value.path).toBe(`/workspaces/${workspaceId}`)
    expect(wrapper.text()).not.toContain('The request could not be started')
  })
})
