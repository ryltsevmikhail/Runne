import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'
import { clearDraft } from '../model/pending-run'
import TaskComposer from './TaskComposer.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const firstToken = '018f2e3a-7000-7000-8000-000000000214'
const secondToken = '018f2e3a-7000-7000-8000-000000000215'
const firstRunId = '018f2e3a-7000-7000-8000-000000000210'

class MemoryStorage implements Storage {
  private values = new Map<string, string>()
  get length() { return this.values.size }
  clear() { this.values.clear() }
  getItem(key: string) { return this.values.get(key) ?? null }
  key(index: number) { return [...this.values.keys()][index] ?? null }
  removeItem(key: string) { this.values.delete(key) }
  setItem(key: string, value: string) { this.values.set(key, String(value)) }
}

const storage = new MemoryStorage()
const authority = {
  provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
  model: { status: 'unavailable', reason: 'runtime_projection_missing' },
  policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
} as const
function preflight(recoveryToken: string) {
  return { status: 'ready' as const, generation: 7, projectId, workspaceId, conversationId,
    canStart: true, startUnavailableReason: null, authority, draftPolicy: 'memory_only' as const, recoveryToken }
}

async function mountComposer(overrides: Record<string, unknown>) {
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div />' } },
    { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
  ] })
  await router.push(`/workspaces/${workspaceId}`); await router.isReady()
  const wrapper = mount(TaskComposer, { props: { projectId, workspaceId, storage, ...overrides }, global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router }
}

describe('managed TaskComposer cross-window identity', () => {
  it('does not let a stale accepted window clear a sibling window recovery token', async () => {
    storage.clear(); clearDraft(workspaceId)
    const first = await mountComposer({
      prepare: async () => preflight(firstToken),
      start: async () => ({ status: 'accepted', taskRunId: firstRunId, streamVersion: 2, recoveryToken: firstToken }),
    })
    await first.wrapper.get('textarea').setValue('Accepted first task')
    await first.wrapper.get('form').trigger('submit'); await flushPromises()
    expect(first.router.currentRoute.value.params.taskRunId).toBe(firstRunId)

    const second = await mountComposer({
      prepare: async () => preflight(secondToken),
      start: async () => ({ status: 'uncertain', taskRunId: null, streamVersion: null, recoveryToken: secondToken }),
      recover: async () => ({ status: 'uncertain', taskRunId: null, streamVersion: null, workspaceId: null, conversationId: null }),
    })
    await second.wrapper.get('button').trigger('click'); await flushPromises()
    await second.wrapper.get('textarea').setValue('Second task')
    await second.wrapper.get('form').trigger('submit'); await flushPromises()
    const key = `runne:managed-task-run:${workspaceId}`
    const secondPending = storage.getItem(key)
    expect(JSON.parse(secondPending ?? '{}').recoveryToken).toBe(secondToken)

    await first.wrapper.get('button').trigger('click'); await flushPromises()
    expect(storage.getItem(key)).toBe(secondPending)
    expect(first.wrapper.text()).toContain('The start result is uncertain')
    expect(first.wrapper.text()).not.toContain('This task was accepted')
    first.wrapper.unmount(); second.wrapper.unmount(); clearDraft(workspaceId)
  })
})
