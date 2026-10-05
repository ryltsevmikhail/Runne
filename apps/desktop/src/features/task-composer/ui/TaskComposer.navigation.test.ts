import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h, onBeforeUnmount } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ManagedTaskRunPreflight } from '@/entities/task-run/api/managed-task-run'
import TaskComposer from './TaskComposer.vue'

const projectId = '018f2e3a-7000-7000-8000-000000000213'
const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const conversationId = '018f2e3a-7000-7000-8000-000000000211'
const recoveryToken = '018f2e3a-7000-7000-8000-000000000214'
const taskRunId = '018f2e3a-7000-7000-8000-000000000210'
const pendingKey = `runne:managed-task-run:${workspaceId}`
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
const mounted: Array<() => void> = []
let routeComposerUnmounted = 0
const ready: ManagedTaskRunPreflight = {
  status: 'ready', generation: 7, projectId, workspaceId, conversationId, canStart: true,
  startUnavailableReason: null, recoveryToken, draftPolicy: 'memory_only',
  authority: {
    provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
    model: { status: 'unavailable', reason: 'runtime_projection_missing' },
    policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
  },
}
afterEach(() => { mounted.splice(0).forEach(dispose => dispose()) })

async function render() {
  storage.clear()
  routeComposerUnmounted = 0
  const workspace = defineComponent({
    setup() {
      onBeforeUnmount(() => { routeComposerUnmounted += 1 })
      return () => h(TaskComposer, {
        projectId, workspaceId, storage,
        prepare: vi.fn(async () => ready),
        start: vi.fn(async () => ({ status: 'accepted' as const, taskRunId, streamVersion: 2 as const, recoveryToken })),
      })
    },
  })
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/workspaces/:workspaceId', name: 'workspace', component: workspace },
    { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div>Timeline</div>' } },
  ] })
  await router.push(`/workspaces/${workspaceId}`)
  await router.isReady()
  const wrapper = mount(defineComponent(() => () => h(RouterView)), { global: { plugins: [router] } })
  let disposed = false
  const dispose = () => { if (!disposed) { disposed = true; wrapper.unmount() } }
  mounted.push(dispose)
  await flushPromises()
  return { wrapper, router, dispose }
}

describe('accepted navigation receipt', () => {
  it('persists the exact accepted receipt after navigation unmounts the composer', async () => {
    const { wrapper, router } = await render()
    await wrapper.get('textarea').setValue('accepted memory draft')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
    expect(routeComposerUnmounted).toBe(1)
    expect(JSON.parse(storage.getItem(pendingKey) ?? '{}')).toMatchObject({
      recoveryToken, acceptedTaskRunId: taskRunId, navigated: true,
    })
  })

  it('does not acknowledge navigation after another intent replaces the accepted receipt', async () => {
    const { wrapper, router } = await render()
    let release: (() => void) | undefined
    router.beforeEach(async to => {
      if (to.name === 'task-run') await new Promise<void>(resolve => { release = resolve })
    })
    await wrapper.get('textarea').setValue('accepted memory draft')
    await wrapper.get('form').trigger('submit')
    await vi.waitFor(() => expect(release).toBeDefined())
    const newer = {
      recoveryToken: '018f2e3a-7000-7000-8000-000000000215', projectId, workspaceId, conversationId,
      acceptedTaskRunId: taskRunId,
    }
    storage.setItem(pendingKey, JSON.stringify(newer))
    release?.()
    await flushPromises()

    expect(router.currentRoute.value.params.taskRunId).toBe(taskRunId)
    expect(JSON.parse(storage.getItem(pendingKey) ?? '{}')).toEqual(newer)
  })

  it('leaves the accepted receipt unacknowledged when the router redirects elsewhere', async () => {
    const { wrapper, router } = await render()
    router.beforeEach(to => to.name === 'task-run' ? { name: 'workspace', params: { workspaceId } } : true)
    await wrapper.get('textarea').setValue('accepted memory draft')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('workspace')
    expect(JSON.parse(storage.getItem(pendingKey) ?? '{}')).toMatchObject({
      recoveryToken, acceptedTaskRunId: taskRunId,
    })
    expect(JSON.parse(storage.getItem(pendingKey) ?? '{}').navigated).toBe(false)
  })
})
