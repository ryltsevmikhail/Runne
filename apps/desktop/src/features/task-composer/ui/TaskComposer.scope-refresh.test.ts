import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ManagedTaskRunPreflight } from '@/entities/task-run/api/managed-task-run'
import TaskComposer from './TaskComposer.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const recoveryToken = '018f2e3a-7000-7000-8000-000000000214'
const ready: ManagedTaskRunPreflight = {
  status: 'ready', generation: 7, projectId, workspaceId,
  conversationId: '018f2e3a-7000-7000-8000-000000000211', canStart: true,
  startUnavailableReason: null, recoveryToken, draftPolicy: 'memory_only',
  authority: {
    provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
    model: { status: 'unavailable', reason: 'runtime_projection_missing' },
    policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
  },
}
const storage: Storage = {
  length: 0, clear() {}, getItem() { return null }, key() { return null }, removeItem() {}, setItem() {},
}
const mounted: Array<{ wrapper: ReturnType<typeof mount>, disposed: boolean }> = []
afterEach(() => {
  for (const entry of mounted.splice(0)) if (!entry.disposed) entry.wrapper.unmount()
})

describe('TaskComposer scope refresh privacy', () => {
  it('keeps a known draft hidden when same-scope preflight refresh fails', async () => {
    let prepares = 0
    const prepare = vi.fn(async () => {
      prepares += 1
      if (prepares > 1) throw new Error('native preflight unavailable')
      return ready
    })
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/workspaces/:workspaceId', name: 'workspace', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push(`/workspaces/${workspaceId}`)
    const wrapper = mount(TaskComposer, {
      props: { projectId, workspaceId, storage, prepare },
      global: { plugins: [router] },
    })
    mounted.push({ wrapper, disposed: false })
    await flushPromises()
    await wrapper.get('textarea').setValue('known local memory draft')

    window.dispatchEvent(new StorageEvent('storage', { key: `runne:managed-task-run:${workspaceId}` }))
    await vi.waitFor(() => expect(wrapper.text()).toContain('Task start is unavailable'))

    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).not.toContain('known local memory draft')
    expect(wrapper.text()).not.toContain('Draft held in memory')
  })
})
