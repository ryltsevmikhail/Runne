import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import WorkspaceTaskRunComposer from './WorkspaceTaskRunComposer.vue'

const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
const projectId = '018f2e3a-7000-7000-8000-000000000213'
class MemoryStorage implements Storage {
  get length() { return 0 }
  clear() {}
  getItem() { return null }
  key() { return null }
  removeItem() {}
  setItem() {}
}
const storage = new MemoryStorage()
const mounted: Array<{ unmount: () => void }> = []
const authority = {
  provider: { status: 'unavailable', reason: 'runtime_projection_missing' },
  model: { status: 'unavailable', reason: 'runtime_projection_missing' },
  policy: { status: 'unavailable', reason: 'runtime_projection_missing' },
} as const

describe('workspace TaskComposer mount', () => {
  it('resolves the canonical project and mounts the managed composer', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/workspaces/:workspaceId', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push(`/workspaces/${workspaceId}`); await router.isReady()
    const loadWorkspace = vi.fn(async id => ({ workspaceId: id, projectId, displayName: 'Workspace', version: 1, open: true }))
    const prepare = vi.fn(async project => ({ status: 'ready' as const, generation: 7, projectId: project, workspaceId, conversationId: '018f2e3a-7000-7000-8000-000000000211', canStart: true, startUnavailableReason: null, authority, draftPolicy: 'memory_only' as const, recoveryToken: '018f2e3a-7000-7000-8000-000000000214' }))
    const wrapper = mount(WorkspaceTaskRunComposer, { props: { workspaceId, loadWorkspace, prepare, storage }, global: { plugins: [router] } })
    mounted.push(wrapper)
    await flushPromises()

    expect(loadWorkspace).toHaveBeenCalledWith(workspaceId)
    expect(prepare).toHaveBeenCalledWith(projectId, workspaceId)
    expect(wrapper.get('h2').text()).toBe('Start a managed task')
  })

  it('keeps submit unavailable when canonical workspace lookup fails', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/workspaces/:workspaceId', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push(`/workspaces/${workspaceId}`); await router.isReady()
    const prepare = vi.fn()
    const wrapper = mount(WorkspaceTaskRunComposer, { props: { workspaceId, loadWorkspace: async () => { throw new Error('unavailable') }, prepare, storage }, global: { plugins: [router] } })
    mounted.push(wrapper)
    await flushPromises()
    expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
    expect(prepare).not.toHaveBeenCalled()
  })

  it('retries canonical workspace lookup when runtime readiness returns', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/workspaces/:workspaceId', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push(`/workspaces/${workspaceId}`); await router.isReady()
    const loadWorkspace = vi.fn()
      .mockRejectedValueOnce(new Error('runtime disconnected'))
      .mockResolvedValueOnce({ workspaceId, projectId, displayName: 'Workspace', version: 1, open: true })
    const prepare = vi.fn(async project => ({ status: 'ready' as const, generation: 7, projectId: project, workspaceId, conversationId: '018f2e3a-7000-7000-8000-000000000211', canStart: true, startUnavailableReason: null, authority, draftPolicy: 'memory_only' as const, recoveryToken: '018f2e3a-7000-7000-8000-000000000214' }))
    const wrapper = mount(WorkspaceTaskRunComposer, { props: { workspaceId, loadWorkspace, prepare, storage }, global: { plugins: [router] } })
    mounted.push(wrapper)
    await flushPromises()
    expect(loadWorkspace).toHaveBeenCalledTimes(1)
    await wrapper.setProps({ disabled: true }); await wrapper.setProps({ disabled: false }); await flushPromises()
    expect(loadWorkspace).toHaveBeenCalledTimes(2)
    expect(prepare).toHaveBeenCalledWith(projectId, workspaceId)
  })

  it('ignores a stale workspace lookup rejection after the route scope changes', async () => {
    const nextWorkspace = '018f2e3a-7000-7000-8000-000000000216'
    const nextProject = '018f2e3a-7000-7000-8000-000000000215'
    const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/workspaces/:workspaceId', component: { template: '<div />' } },
      { path: '/task-runs/:taskRunId', name: 'task-run', component: { template: '<div />' } },
    ] })
    await router.push(`/workspaces/${workspaceId}`); await router.isReady()
    let rejectOld: ((error: Error) => void) | undefined
    const loadWorkspace = vi.fn((id: string) => id === workspaceId
      ? new Promise<never>((_, reject) => { rejectOld = reject })
      : Promise.resolve({ workspaceId: id, projectId: nextProject, displayName: 'Next', version: 1, open: true }))
    const prepare = vi.fn(async (project: string, id: string) => ({ status: 'ready' as const, generation: 7, projectId: project, workspaceId: id, conversationId: '018f2e3a-7000-7000-8000-000000000211', canStart: true, startUnavailableReason: null, authority, draftPolicy: 'memory_only' as const, recoveryToken: '018f2e3a-7000-7000-8000-000000000214' }))
    const wrapper = mount(WorkspaceTaskRunComposer, { props: { workspaceId, loadWorkspace, prepare, storage }, global: { plugins: [router] } })
    mounted.push(wrapper)
    await wrapper.setProps({ workspaceId: nextWorkspace }); await flushPromises()
    rejectOld?.(new Error('late old-scope failure')); await flushPromises()
    expect(prepare).toHaveBeenCalledWith(nextProject, nextWorkspace)
    await wrapper.get('textarea').setValue('Current project draft')
    expect((wrapper.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
  })
})

afterEach(() => { for (const wrapper of mounted.splice(0)) wrapper.unmount() })
